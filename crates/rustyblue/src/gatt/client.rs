//! GATT Client implementation
//!
//! This module provides a client for interacting with GATT servers.

use crate::att::{
    AttClient, AttError, AttErrorCode, AttPermissions, AttResult, AttributeData,
    ExecuteWriteRequest, ExecuteWriteResponse, FindByTypeValueRequest, FindByTypeValueResponse,
    FindInformationRequest, HandleUuidPair, HandleValueConfirmation, HandleValueIndication,
    HandleValueNotification, PrepareWriteRequest, PrepareWriteResponse, ReadBlobRequest,
    ReadBlobResponse, ReadByGroupTypeRequest, ReadByTypeRequest, ReadMultipleRequest,
    ReadMultipleResponse, ReadRequest, ReadResponse, SecurityLevel, WriteRequest, ATT_CID,
    ATT_DEFAULT_MTU, ATT_HANDLE_MAX, ATT_HANDLE_MIN, ATT_MAX_MTU, CHARACTERISTIC_UUID,
    CLIENT_CHAR_CONFIG_UUID, PRIMARY_SERVICE_UUID,
};
use crate::error::Error;
use crate::gap::BdAddr;
use crate::gatt::server::Descriptor;
use crate::gatt::types::{Characteristic, CharacteristicProperty, Service, Uuid};
use crate::hci::constants::{
    EVT_CMD_COMPLETE, EVT_CMD_STATUS, EVT_DISCONN_COMPLETE, EVT_LE_CONN_COMPLETE,
    EVT_LE_META_EVENT, OCF_LE_CREATE_CONNECTION, OCF_LE_SET_SCAN_PARAMETERS, OGF_LE,
};
use crate::hci::{HciCommand, HciEvent, HciSocket};
use crate::l2cap::{/*L2capError,*/ ConnectionType, L2capManager};
use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use std::time::Instant;

/// Error types specific to GATT operations
#[derive(Debug, thiserror::Error)]
pub enum GattError {
    #[error("HCI error: {0}")]
    HciError(String),

    #[error("Device not connected")]
    NotConnected,

    #[error("Service not found")]
    ServiceNotFound,

    #[error("Characteristic not found")]
    CharacteristicNotFound,

    #[error("Attribute operation not permitted")]
    NotPermitted,

    #[error("Read operation timed out")]
    Timeout,

    #[error("Invalid data received")]
    InvalidData,

    #[error("ATT error: {0}")]
    AttError(#[from] AttError),

    #[error("L2CAP error: {0}")]
    L2capError(String),
}

impl From<Error> for GattError {
    fn from(err: Error) -> Self {
        match err {
            Error::Hci(hci_err) => GattError::HciError(hci_err.to_string()),
            Error::Timeout => GattError::Timeout,
            Error::NotConnected => GattError::NotConnected,
            _ => GattError::HciError(err.to_string()),
        }
    }
}

/// Defines the connection state of a GATT client
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

/// LE Connection Complete Event data
#[derive(Debug, Clone)]
pub struct LeConnectionComplete {
    pub status: u8,
    pub connection_handle: u16,
    pub role: u8,
    pub peer_address_type: u8,
    pub peer_address: [u8; 6],
    pub conn_interval: u16,
    pub conn_latency: u16,
    pub supervision_timeout: u16,
    pub master_clock_accuracy: u8,
}

impl LeConnectionComplete {
    /// Parse an LE Connection Complete event from an HCI Meta Event
    pub fn parse(event: &HciEvent) -> Option<Self> {
        if event.event_code != EVT_LE_META_EVENT || event.parameters.is_empty() {
            return None;
        }

        if event.parameters[0] != EVT_LE_CONN_COMPLETE {
            return None;
        }

        if event.parameters.len() < 19 {
            return None;
        }

        let status = event.parameters[1];
        let handle = u16::from_le_bytes([event.parameters[2], event.parameters[3]]);
        let role = event.parameters[4];
        let peer_address_type = event.parameters[5];

        let mut peer_address = [0u8; 6];
        peer_address.copy_from_slice(&event.parameters[6..12]);

        let conn_interval = u16::from_le_bytes([event.parameters[12], event.parameters[13]]);
        let conn_latency = u16::from_le_bytes([event.parameters[14], event.parameters[15]]);
        let supervision_timeout = u16::from_le_bytes([event.parameters[16], event.parameters[17]]);
        let master_clock_accuracy = event.parameters[18];

        Some(LeConnectionComplete {
            status,
            connection_handle: handle,
            role,
            peer_address_type,
            peer_address,
            conn_interval,
            conn_latency,
            supervision_timeout,
            master_clock_accuracy,
        })
    }
}

/// Disconnection Complete Event data
#[derive(Debug, Clone)]
pub struct DisconnectionComplete {
    pub status: u8,
    pub connection_handle: u16,
    pub reason: u8,
}

impl DisconnectionComplete {
    /// Parse a Disconnection Complete event
    pub fn parse(event: &HciEvent) -> Option<Self> {
        if event.event_code != EVT_DISCONN_COMPLETE {
            return None;
        }

        if event.parameters.len() < 4 {
            return None;
        }

        let status = event.parameters[0];
        let handle = u16::from_le_bytes([event.parameters[1], event.parameters[2]]);
        let reason = event.parameters[3];

        Some(DisconnectionComplete {
            status,
            connection_handle: handle,
            reason,
        })
    }
}

/// Event callback type for connection events
pub type ConnectionCallback = Box<dyn Fn(ConnectionState, u16) + Send + 'static>;

/// Represents the state of the discovery process.
#[derive(Debug, Clone, PartialEq)]
enum DiscoveryState {
    Idle,
    DiscoveringServices(usize), // Current service index being processed (for advancing)
    DiscoveringCharacteristics(usize), // Index of the service whose characteristics are being discovered
    DiscoveringDescriptors(usize, usize), // Service index, Characteristic index
}

/// A client for interacting with a GATT server
pub struct GattClient {
    /// HCI socket for connecting to devices
    socket: HciSocket,
    /// L2CAP manager for ATT communication
    l2cap_manager: Arc<L2capManager>,
    /// ATT client for GATT operations
    att_client: Option<Arc<AttClient>>,
    /// HCI connection handle
    connection_handle: Option<u16>,
    /// Remote device address
    remote_addr: Option<BdAddr>,
    /// Connection state
    state: ConnectionState,

    /// Cache of discovered services and characteristics
    services: RwLock<Vec<Service>>,
    characteristics: RwLock<HashMap<u16, Vec<Characteristic>>>, // Service handle -> characteristics

    /// Add fields for managing discovery state and pending requests if they were part of the deleted code
    pending_discovery: Mutex<Option<DiscoveryState>>,
    discovered_services: Mutex<Vec<Service>>, // Need temporary storage during discovery
    pending_requests: Mutex<VecDeque<PendingRequest>>, // Assuming PendingRequest struct exists or needs definition
    notification_callbacks: Mutex<HashMap<u16, NotificationCallback>>, // Assuming NotificationCallback type exists
    indication_callbacks: Mutex<HashMap<u16, IndicationCallback>>, // Assuming IndicationCallback type exists

    /// Connection event callback
    connection_callback: Option<ConnectionCallback>,
    /// Notification callback
    notification_callback:
        Option<Arc<Mutex<dyn Fn(u16, &[u8]) -> Result<(), GattError> + Send + Sync + 'static>>>,
}

// Define PendingRequest if needed
struct PendingRequest {
    opcode: AttOpcode,
    callback: Option<Box<dyn FnOnce(AttResult<Vec<u8>>) -> AttResult<()>>>, // Assuming AttCallback type
    timestamp: Instant,
}
// Define callback types if needed
type AttCallback = Box<dyn FnOnce(AttResult<Vec<u8>>) -> AttResult<()>>;
type NotificationCallback = Box<dyn Fn(Vec<u8>)>;
type IndicationCallback = Box<dyn Fn(Vec<u8>)>;

impl std::fmt::Debug for GattClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GattClient")
            .field("connection_handle", &self.connection_handle)
            .field("state", &self.state)
            .field("services", &self.services)
            .field("characteristics", &self.characteristics)
            .field(
                "has_connection_callback",
                &self.connection_callback.is_some(),
            )
            .field(
                "has_notification_callback",
                &self.notification_callback.is_some(),
            )
            .finish()
    }
}

impl GattClient {
    /// Create a new GATT client using the given HCI socket and L2CAP manager
    pub fn new(socket: HciSocket, l2cap_manager: Arc<L2capManager>) -> Self {
        GattClient {
            socket,
            l2cap_manager,
            att_client: None,
            connection_handle: None,
            remote_addr: None,
            state: ConnectionState::Disconnected,
            services: RwLock::new(Vec::new()),
            characteristics: RwLock::new(HashMap::new()),
            pending_discovery: Mutex::new(None),
            discovered_services: Mutex::new(Vec::new()),
            pending_requests: Mutex::new(VecDeque::new()),
            notification_callbacks: Mutex::new(HashMap::new()),
            indication_callbacks: Mutex::new(HashMap::new()),
            connection_callback: None,
            notification_callback: None,
        }
    }

    /// Set a callback for connection state changes
    pub fn set_connection_callback(&mut self, callback: ConnectionCallback) {
        self.connection_callback = Some(callback);
    }

    /// Set a callback for characteristic notifications
    pub fn set_notification_callback<F>(&mut self, callback: F)
    where
        F: Fn(u16, &[u8]) -> Result<(), GattError> + Send + Sync + 'static,
    {
        self.notification_callback = Some(Arc::new(Mutex::new(callback)));

        // If we have an ATT client, set its notification callback
        if let Some(att_client) = &self.att_client {
            let notification_callback = self.notification_callback.clone().unwrap();

            att_client.set_notification_callback(move |handle, value| match notification_callback
                .lock()
                .unwrap()(
                handle, value
            ) {
                Ok(()) => Ok(()),
                Err(err) => match err {
                    GattError::AttError(att_err) => Err(att_err),
                    _ => Err(AttError::Unknown("Notification callback error".into())),
                },
            });
        }
    }

    /// Get a reference to the underlying HCI socket
    pub fn socket(&self) -> &HciSocket {
        &self.socket
    }

    /// Get the current connection state
    pub fn connection_state(&self) -> ConnectionState {
        self.state
    }

    /// Get the current connection handle, if connected
    pub fn connection_handle(&self) -> Option<u16> {
        self.connection_handle
    }

    /// Connect to a Bluetooth LE device with the given address
    pub fn connect(&mut self, addr: [u8; 6], addr_type: u8) -> Result<(), GattError> {
        if self.state != ConnectionState::Disconnected {
            return Err(GattError::NotPermitted);
        }

        self.update_state(ConnectionState::Connecting, 0);

        // First set LE scan parameters
        let scan_params = HciCommand::LeSetScanParameters {
            scan_type: 0x01,        // Active scanning
            scan_interval: 0x0010,  // 10 ms
            scan_window: 0x0010,    // 10 ms
            own_address_type: 0x00, // Public address
            filter_policy: 0x00,    // Accept all
        };

        self.socket
            .send_command(&scan_params)
            .map_err(|e| GattError::HciError(e.to_string()))?;

        // Read and check the command complete event
        let event = self
            .socket
            .read_event()
            .map_err(|e| GattError::HciError(e.to_string()))?;

        if !event.is_command_complete(OGF_LE, OCF_LE_SET_SCAN_PARAMETERS) || event.get_status() != 0
        {
            self.update_state(ConnectionState::Disconnected, 0);
            return Err(GattError::HciError("Failed to set scan parameters".into()));
        }

        // Now send the LE Create Connection command
        let conn_params = HciCommand::Raw {
            ogf: OGF_LE,
            ocf: OCF_LE_CREATE_CONNECTION,
            parameters: {
                let mut params = Vec::with_capacity(25);
                // LE scan interval and window
                params.extend_from_slice(&0x0060u16.to_le_bytes()); // 60 ms interval
                params.extend_from_slice(&0x0030u16.to_le_bytes()); // 30 ms window
                                                                    // Initiator filter policy
                params.push(0x00); // Use peer address
                                   // Peer address type
                params.push(addr_type);
                // Peer address
                params.extend_from_slice(&addr);
                // Own address type
                params.push(0x00); // Public
                                   // Connection interval min/max
                params.extend_from_slice(&0x0010u16.to_le_bytes()); // 20 ms min
                params.extend_from_slice(&0x0020u16.to_le_bytes()); // 40 ms max
                                                                    // Connection latency
                params.extend_from_slice(&0x0000u16.to_le_bytes()); // 0 events
                                                                    // Supervision timeout
                params.extend_from_slice(&0x00C8u16.to_le_bytes()); // 2 seconds
                                                                    // Min/max CE length
                params.extend_from_slice(&0x0000u16.to_le_bytes()); // 0 ms min
                params.extend_from_slice(&0x0000u16.to_le_bytes()); // 0 ms max
                params
            },
        };

        self.socket
            .send_command(&conn_params)
            .map_err(|e| GattError::HciError(e.to_string()))?;

        // For the LE Create Connection command, we get a Command Status event
        let event = self
            .socket
            .read_event()
            .map_err(|e| GattError::HciError(e.to_string()))?;

        if event.event_code != EVT_CMD_STATUS || event.parameters.len() < 4 {
            self.update_state(ConnectionState::Disconnected, 0);
            return Err(GattError::HciError("Unexpected event received".into()));
        }

        let status = event.parameters[0];
        if status != 0 {
            self.update_state(ConnectionState::Disconnected, 0);
            return Err(GattError::HciError(format!(
                "Create connection command failed with status: {}",
                status
            )));
        }

        // Convert the address to BdAddr
        let mut bd_addr = [0u8; 6];
        bd_addr.copy_from_slice(&addr);
        self.remote_addr = Some(BdAddr::new(bd_addr));

        // The connection process is now in progress
        // The actual connection complete event will be received asynchronously
        Ok(())
    }

    /// Disconnect from the currently connected device
    pub fn disconnect(&mut self) -> Result<(), GattError> {
        if let Some(handle) = self.connection_handle {
            self.update_state(ConnectionState::Disconnecting, handle);

            // Disconnect the ATT client first
            if let Some(att_client) = &self.att_client {
                if let Err(e) = att_client.disconnect() {
                    return Err(GattError::AttError(e));
                }
            }

            // Then send HCI Disconnect command
            match self.socket.send_command(&HciCommand::Disconnect {
                handle,
                reason: 0x13, // Remote User Terminated Connection
            }) {
                Ok(_) => {}
                Err(e) => return Err(GattError::HciError(e.to_string())),
            }

            // For the Disconnect command, we get a Command Status event
            let event = self
                .socket
                .read_event()
                .map_err(|e| GattError::HciError(e.to_string()))?;

            if event.event_code != EVT_CMD_STATUS || event.parameters.len() < 4 {
                return Err(GattError::HciError("Unexpected event received".into()));
            }

            let status = event.parameters[0];
            if status != 0 {
                return Err(GattError::HciError(format!(
                    "Disconnect command failed with status: {}",
                    status
                )));
            }

            // The disconnection process is now in progress
            // The actual disconnection complete event will be received asynchronously
            Ok(())
        } else {
            Err(GattError::NotConnected)
        }
    }

    /// Process incoming HCI events, handling connection events automatically
    pub fn process_events(&mut self, timeout: Option<Duration>) -> Result<(), GattError> {
        // Process ATT client timeouts
        if let Some(att_client) = &self.att_client {
            att_client.process_timeouts().map_err(GattError::AttError)?;
        }

        // Process HCI events
        let event = match self.socket.read_event_timeout(timeout) {
            Ok(evt) => evt,
            Err(e) => {
                if let crate::error::HciError::ReceiveError(io_err) = &e {
                    if io_err.kind() == std::io::ErrorKind::TimedOut {
                        return Ok(());
                    }
                }
                return Err(GattError::HciError(e.to_string()));
            }
        };

        // Handle specific events of interest
        match event.event_code {
            EVT_LE_META_EVENT => {
                if event.parameters.is_empty() {
                    return Ok(());
                }

                let subevent = event.parameters[0];
                match subevent {
                    EVT_LE_CONN_COMPLETE => {
                        if let Some(conn_complete) = LeConnectionComplete::parse(&event) {
                            self.handle_connection_complete(conn_complete)?;
                        }
                    }
                    // Handle other LE meta events as needed
                    _ => {}
                }
            }
            EVT_DISCONN_COMPLETE => {
                if let Some(disc_complete) = DisconnectionComplete::parse(&event) {
                    self.handle_disconnection_complete(disc_complete);
                }
            }
            // For ATT PDUs that come over ACL, we need to process them through the L2CAP manager
            EVT_DATA_BUFFER_OVERFLOW => {
                // Handle data buffer overflow
            }
            // Handle other events as needed
            _ => {}
        }

        Ok(())
    }

    /// Handle a connection complete event
    fn handle_connection_complete(&mut self, event: LeConnectionComplete) -> Result<(), GattError> {
        if event.status == 0 {
            // Connection successful
            self.connection_handle = Some(event.connection_handle);

            // Create ATT client for this connection
            if let Some(addr) = self.remote_addr {
                let att_client = Arc::new(AttClient::new(addr, self.l2cap_manager.clone()));

                // Set notification callback if we have one
                if let Some(notification_callback) = &self.notification_callback {
                    let nc = notification_callback.clone();
                    att_client.set_notification_callback(move |handle, value| {
                        match nc.lock().unwrap()(handle, value) {
                            Ok(()) => Ok(()),
                            Err(err) => match err {
                                GattError::AttError(att_err) => Err(att_err),
                                _ => Err(AttError::Unknown("Notification callback error".into())),
                            },
                        }
                    });
                }

                // Connect ATT channel
                att_client
                    .connect(event.connection_handle)
                    .map_err(GattError::AttError)?;

                // Exchange MTU (request larger MTU if server supports it)
                let _ = att_client.exchange_mtu(ATT_MAX_MTU);

                self.att_client = Some(att_client);
            }

            self.update_state(ConnectionState::Connected, event.connection_handle);
        } else {
            // Connection failed
            self.connection_handle = None;
            self.att_client = None;
            self.update_state(ConnectionState::Disconnected, 0);
        }

        Ok(())
    }

    /// Handle a disconnection complete event
    fn handle_disconnection_complete(&mut self, event: DisconnectionComplete) {
        if let Some(handle) = self.connection_handle {
            if handle == event.connection_handle {
                // This is a disconnection for our connection
                self.connection_handle = None;
                self.att_client = None;
                self.remote_addr = None;

                {
                    let mut services = self.services.write().unwrap();
                    services.clear();
                }

                {
                    let mut characteristics = self.characteristics.write().unwrap();
                    characteristics.clear();
                }

                self.update_state(ConnectionState::Disconnected, 0);
            }
        }
    }

    /// Update the connection state and call the callback if registered
    fn update_state(&mut self, state: ConnectionState, handle: u16) {
        self.state = state;
        if let Some(callback) = &self.connection_callback {
            callback(state, handle);
        }
    }

    /// Discover all services on the connected device
    pub fn discover_services(&mut self) -> Result<Vec<Service>, GattError> {
        if self.state != ConnectionState::Connected {
            return Err(GattError::NotConnected);
        }

        let att_client = self.att_client.as_ref().ok_or(GattError::NotConnected)?;

        // Clear existing services
        {
            let mut services = self.services.write().unwrap();
            services.clear();
        }

        {
            let mut characteristics = self.characteristics.write().unwrap();
            characteristics.clear();
        }

        // Read all primary services using Read By Group Type Request
        let mut services = Vec::new();
        let mut start_handle = ATT_HANDLE_MIN;
        let end_handle = ATT_HANDLE_MAX;

        // Iterate through all primary services
        loop {
            // Read primary services
            let result = match att_client.read_by_group_type(
                start_handle,
                end_handle,
                &Uuid::from_u16(PRIMARY_SERVICE_UUID),
            ) {
                Ok(result) => result,
                Err(e) => {
                    // If we get Attribute Not Found, we've read all services
                    if let AttError::AttributeNotFound = e {
                        break;
                    }
                    return Err(GattError::AttError(e));
                }
            };

            // No more services found
            if result.is_empty() {
                break;
            }

            // Process the discovered services
            for (handle, end_group_handle, value) in result {
                // Parse the UUID from the value
                let uuid = if value.len() == 2 {
                    // 16-bit UUID
                    let uuid16 = u16::from_le_bytes([value[0], value[1]]);
                    Uuid::from_u16(uuid16)
                } else if value.len() == 16 {
                    // 128-bit UUID
                    let mut uuid_bytes = [0u8; 16];
                    uuid_bytes.copy_from_slice(&value[0..16]);
                    Uuid::from_bytes(&uuid_bytes)
                } else {
                    continue; // Invalid UUID length
                };

                // Create service
                let service = Service {
                    uuid,
                    is_primary: true,
                    start_handle: handle,
                    end_handle: end_group_handle,
                };

                // Add to our list
                services.push(service);

                // Update start handle for next iteration
                if end_group_handle == ATT_HANDLE_MAX {
                    break;
                }
                start_handle = end_group_handle + 1;
            }

            // If we've reached the end, break out
            if start_handle > end_handle {
                break;
            }
        }

        // Now do the same for secondary services if needed
        // (skipped for brevity)

        // Store the discovered services
        {
            let mut services_lock = self.services.write().unwrap();
            *services_lock = services.clone();
        }

        Ok(services)
    }

    /// Discover characteristics for a specific service
    pub fn discover_characteristics(
        &mut self,
        service: &Service,
    ) -> Result<Vec<Characteristic>, GattError> {
        if self.state != ConnectionState::Connected {
            return Err(GattError::NotConnected);
        }

        let att_client = self.att_client.as_ref().ok_or(GattError::NotConnected)?;

        // Clear existing characteristics for this service
        {
            let mut characteristics = self.characteristics.write().unwrap();
            characteristics.remove(&service.start_handle);
        }

        // Read all characteristics using Read By Type Request
        let mut characteristics = Vec::new();
        let mut start_handle = service.start_handle;
        let end_handle = service.end_handle;

        // Iterate through all characteristics
        loop {
            // Read characteristic declarations
            let result = match att_client.read_by_type(
                start_handle,
                end_handle,
                &Uuid::from_u16(CHARACTERISTIC_UUID),
            ) {
                Ok(result) => result,
                Err(e) => {
                    // If we get Attribute Not Found, we've read all characteristics
                    if let AttError::AttributeNotFound = e {
                        break;
                    }
                    return Err(GattError::AttError(e));
                }
            };

            // No more characteristics found
            if result.is_empty() {
                break;
            }

            // Process the discovered characteristics
            for (handle, value) in result {
                // Parse the characteristic declaration
                // Format: [properties(1 byte), value handle(2 bytes), UUID(2 or 16 bytes)]
                if value.len() < 5 {
                    continue; // Invalid characteristic declaration
                }

                // Fix E0423: Use from_bits_truncate provided by bitflags
                let properties = CharacteristicProperty::from_bits_truncate(value[0]);
                let value_handle = u16::from_le_bytes([value[1], value[2]]);

                // Parse the UUID
                let uuid = if value.len() == 5 + 2 {
                    // 16-bit UUID
                    let uuid16 = u16::from_le_bytes([value[3], value[4]]);
                    Uuid::from_u16(uuid16)
                } else if value.len() == 5 + 16 {
                    // 128-bit UUID
                    let mut uuid_bytes = [0u8; 16];
                    uuid_bytes.copy_from_slice(&value[3..19]);
                    Uuid::from_bytes(&uuid_bytes)
                } else {
                    continue; // Invalid UUID length
                };

                // Create characteristic
                let characteristic = Characteristic {
                    uuid,
                    declaration_handle: handle,
                    value_handle,
                    properties,
                };

                // Add to our list
                characteristics.push(characteristic);

                // Update start handle for next iteration
                start_handle = handle + 1;
            }

            // If we've reached the end, break out
            if start_handle > end_handle {
                break;
            }
        }

        // Store the discovered characteristics
        {
            let mut chars_lock = self.characteristics.write().unwrap();
            chars_lock.insert(service.start_handle, characteristics.clone());
        }

        Ok(characteristics)
    }

    /// Read a characteristic's value
    pub fn read_characteristic(
        &self,
        characteristic: &Characteristic,
    ) -> Result<Vec<u8>, GattError> {
        if self.state != ConnectionState::Connected {
            return Err(GattError::NotConnected);
        }

        if !characteristic.properties.can_read() {
            return Err(GattError::NotPermitted);
        }

        let att_client = self.att_client.as_ref().ok_or(GattError::NotConnected)?;

        // Read the characteristic value using ATT Read Request
        let value = att_client
            .read(characteristic.value_handle)
            .map_err(GattError::AttError)?;

        Ok(value)
    }

    /// Write to a characteristic with response
    pub fn write_characteristic(
        &self,
        characteristic: &Characteristic,
        data: &[u8],
    ) -> Result<(), GattError> {
        if self.state != ConnectionState::Connected {
            return Err(GattError::NotConnected);
        }

        if !characteristic.properties.can_write() {
            return Err(GattError::NotPermitted);
        }

        let att_client = self.att_client.as_ref().ok_or(GattError::NotConnected)?;

        // Write the characteristic value using ATT Write Request
        att_client
            .write(characteristic.value_handle, data)
            .map_err(GattError::AttError)?;

        Ok(())
    }

    /// Write to a characteristic without response
    pub fn write_characteristic_without_response(
        &self,
        characteristic: &Characteristic,
        data: &[u8],
    ) -> Result<(), GattError> {
        if self.state != ConnectionState::Connected {
            return Err(GattError::NotConnected);
        }

        if !characteristic.properties.can_write_without_response() {
            return Err(GattError::NotPermitted);
        }

        let att_client = self.att_client.as_ref().ok_or(GattError::NotConnected)?;

        // Write the characteristic value using ATT Write Command
        att_client
            .write_command(characteristic.value_handle, data)
            .map_err(GattError::AttError)?;

        Ok(())
    }

    /// Find a service by UUID
    pub fn find_service(&self, uuid: &Uuid) -> Option<Service> {
        let services = self.services.read().unwrap();
        services.iter().find(|s| &s.uuid == uuid).cloned()
    }

    /// Find a characteristic by UUID within a service
    pub fn find_characteristic(&self, service: &Service, uuid: &Uuid) -> Option<Characteristic> {
        let characteristics = self.characteristics.read().unwrap();
        characteristics
            .get(&service.start_handle)
            .and_then(|chars| chars.iter().find(|c| &c.uuid == uuid).cloned())
    }

    /// Enable notifications for a characteristic
    pub fn enable_notifications(&self, characteristic: &Characteristic) -> Result<(), GattError> {
        if self.state != ConnectionState::Connected {
            return Err(GattError::NotConnected);
        }

        if !characteristic.properties.can_notify() {
            return Err(GattError::NotPermitted);
        }

        let att_client = self.att_client.as_ref().ok_or(GattError::NotConnected)?;

        // Find the Client Characteristic Configuration descriptor
        let result = att_client
            .find_information(
                characteristic.value_handle + 1,
                characteristic.value_handle + 10, // Arbitrary range to search
            )
            .map_err(GattError::AttError)?;

        // Look for the CCCD UUID (0x2902)
        let cccd_handle = result
            .iter()
            .find(|(_, uuid)| uuid == &Uuid::from_u16(CLIENT_CHAR_CONFIG_UUID))
            .map(|(handle, _)| *handle)
            .ok_or(GattError::CharacteristicNotFound)?;

        // Write to CCCD to enable notifications (0x0001)
        att_client
            .write(cccd_handle, &[0x01, 0x00])
            .map_err(GattError::AttError)?;

        Ok(())
    }

    /// Enable indications for a characteristic
    pub fn enable_indications(&self, characteristic: &Characteristic) -> Result<(), GattError> {
        if self.state != ConnectionState::Connected {
            return Err(GattError::NotConnected);
        }

        if !characteristic.properties.can_indicate() {
            return Err(GattError::NotPermitted);
        }

        let att_client = self.att_client.as_ref().ok_or(GattError::NotConnected)?;

        // Find the Client Characteristic Configuration descriptor
        let result = att_client
            .find_information(
                characteristic.value_handle + 1,
                characteristic.value_handle + 10, // Arbitrary range to search
            )
            .map_err(GattError::AttError)?;

        // Look for the CCCD UUID (0x2902)
        let cccd_handle = result
            .iter()
            .find(|(_, uuid)| uuid == &Uuid::from_u16(CLIENT_CHAR_CONFIG_UUID))
            .map(|(handle, _)| *handle)
            .ok_or(GattError::CharacteristicNotFound)?;

        // Write to CCCD to enable indications (0x0002)
        att_client
            .write(cccd_handle, &[0x02, 0x00])
            .map_err(GattError::AttError)?;

        Ok(())
    }

    /// Disable notifications and indications for a characteristic
    pub fn disable_notifications_and_indications(
        &self,
        characteristic: &Characteristic,
    ) -> Result<(), GattError> {
        if self.state != ConnectionState::Connected {
            return Err(GattError::NotConnected);
        }

        let att_client = self.att_client.as_ref().ok_or(GattError::NotConnected)?;

        // Find the Client Characteristic Configuration descriptor
        let result = att_client
            .find_information(
                characteristic.value_handle + 1,
                characteristic.value_handle + 10, // Arbitrary range to search
            )
            .map_err(GattError::AttError)?;

        // Look for the CCCD UUID (0x2902)
        let cccd_handle = result
            .iter()
            .find(|(_, uuid)| uuid == &Uuid::from_u16(CLIENT_CHAR_CONFIG_UUID))
            .map(|(handle, _)| *handle)
            .ok_or(GattError::CharacteristicNotFound)?;

        // Write to CCCD to disable notifications/indications (0x0000)
        att_client
            .write(cccd_handle, &[0x00, 0x00])
            .map_err(GattError::AttError)?;

        Ok(())
    }

    fn handle_att_pdu(&mut self, pdu: &[u8]) -> AttResult<()> {
        if pdu.is_empty() {
            return Err(AttError::InvalidPdu);
        }
        let opcode_byte = pdu[0];
        let data = &pdu[1..];

        trace!(
            "Received ATT PDU: Opcode=0x{:02X}, Data={:?}",
            opcode_byte,
            data
        );

        match AttOpcode::try_from(opcode_byte) {
            Ok(AttOpcode::ReadByTypeResponse) => {
                if data.len() < 1 {
                    return Err(AttError::InvalidPdu);
                }
                let length = data[0] as usize;
                if (length < 7) || (data.len() < 1 + length) {
                    return Err(AttError::InvalidPdu);
                }
                let mut characteristics = Vec::new();
                let mut current_pos = 1;
                while current_pos + length <= data.len() {
                    let decl_handle =
                        u16::from_le_bytes([data[current_pos], data[current_pos + 1]]);
                    let decl_value = &data[current_pos + 2..current_pos + length];
                    if decl_value.len() < 3 {
                        warn!("Characteristic declaration value too short");
                        current_pos += length;
                        continue;
                    }
                    let properties = CharacteristicProperty::from_bits_truncate(decl_value[0]);
                    let value_handle = u16::from_le_bytes([decl_value[1], decl_value[2]]);
                    let uuid_bytes = &decl_value[3..];
                    let uuid_result: Result<Uuid, AttError> = if uuid_bytes.len() == 2 {
                        let uuid16 = u16::from_le_bytes([uuid_bytes[0], uuid_bytes[1]]);
                        Ok(Uuid::from_u16(uuid16))
                    } else if uuid_bytes.len() == 16 {
                        Uuid::from_bytes(uuid_bytes).ok_or(AttError::InvalidPdu)
                    } else {
                        Err(AttError::InvalidPdu)
                    };

                    match uuid_result {
                        Ok(uuid) => {
                            characteristics.push(Characteristic {
                                declaration_handle: decl_handle,
                                value_handle,
                                properties,
                                uuid,
                            });
                        }
                        Err(_) => {
                            warn!("Invalid UUID found in characteristic declaration");
                        }
                    }
                    current_pos += length;
                }

                let mut pending_discovery_guard = self.pending_discovery.lock().unwrap();
                if let Some(discovery_state) = pending_discovery_guard.as_mut() {
                    if let DiscoveryState::DiscoveringCharacteristics(service_idx) = discovery_state
                    {
                        let mut discovered_services_guard =
                            self.discovered_services.lock().unwrap();
                        if let Some(service) = discovered_services_guard.get_mut(*service_idx) {
                            drop(discovered_services_guard);
                            let mut characteristics_cache = self.characteristics.write().unwrap();
                            characteristics_cache.insert(service.start_handle, characteristics);
                        } else {
                            warn!("Service index out of bounds during characteristic discovery");
                            drop(discovered_services_guard);
                        }
                        drop(pending_discovery_guard);
                        self.advance_discovery_state()?;
                    } else {
                        warn!(
                            "Received ReadByTypeResponse for characteristics in unexpected state"
                        );
                    }
                } else {
                    warn!("Received ReadByTypeResponse with no pending discovery state");
                }
                Ok(())
            }
            Ok(AttOpcode::ReadByGroupTypeResponse) => {
                if data.len() < 1 {
                    return Err(AttError::InvalidPdu);
                }
                let length = data[0] as usize;
                if (length < 6) || (data.len() < 1 + length) {
                    return Err(AttError::InvalidPdu);
                }
                let mut services = Vec::new();
                let mut current_pos = 1;
                while current_pos + length <= data.len() {
                    let start_handle =
                        u16::from_le_bytes([data[current_pos], data[current_pos + 1]]);
                    let end_handle =
                        u16::from_le_bytes([data[current_pos + 2], data[current_pos + 3]]);
                    let uuid_bytes = &data[current_pos + 4..current_pos + length];
                    let uuid_result: Result<Uuid, AttError> = if uuid_bytes.len() == 2 {
                        let uuid16 = u16::from_le_bytes([uuid_bytes[0], uuid_bytes[1]]);
                        Ok(Uuid::from_u16(uuid16))
                    } else if uuid_bytes.len() == 16 {
                        Uuid::from_bytes(uuid_bytes).ok_or(AttError::InvalidPdu)
                    } else {
                        Err(AttError::InvalidPdu)
                    };
                    match uuid_result {
                        Ok(uuid) => {
                            services.push(Service {
                                start_handle,
                                end_handle,
                                uuid,
                                is_primary: true,
                            });
                        }
                        Err(_) => {
                            warn!("Invalid UUID found in group response");
                        }
                    }
                    current_pos += length;
                }
                let mut discovered_services_guard = self.discovered_services.lock().unwrap();
                *discovered_services_guard = services;
                let mut pending_discovery_guard = self.pending_discovery.lock().unwrap();
                if !discovered_services_guard.is_empty() {
                    *pending_discovery_guard = Some(DiscoveryState::DiscoveringCharacteristics(0));
                    drop(discovered_services_guard);
                    drop(pending_discovery_guard);
                    self.advance_discovery_state()?;
                } else {
                    *pending_discovery_guard = Some(DiscoveryState::Idle);
                    info!("No primary services found.");
                }
                Ok(())
            }
            Ok(AttOpcode::PrepareWriteResponse) => {
                let response = PrepareWriteResponse::parse(pdu)?;
                // Find pending request and verify response
                let mut requests = self.pending_requests.lock().unwrap();
                if let Some(req) = requests.front_mut() {
                    if req.opcode == AttOpcode::PrepareWriteRequest {
                        // TODO: Verify response matches request data if needed
                        let callback = req.callback.take().ok_or(AttError::InvalidState)?;
                        // Prepare Write Response itself doesn't carry substantial data for the callback usually
                        callback(Ok(Vec::new()))?;
                        requests.pop_front();
                        Ok(())
                    } else {
                        warn!(
                            "Received PrepareWriteResponse for non-prepare-write request: {:?}",
                            req.opcode
                        );
                        Err(AttError::UnexpectedResponse)
                    }
                } else {
                    warn!("Received PrepareWriteResponse with no pending request");
                    Err(AttError::UnexpectedResponse)
                }
            }
            Ok(AttOpcode::ExecuteWriteResponse) => {
                // Find pending request and complete it
                let mut requests = self.pending_requests.lock().unwrap();
                if let Some(req) = requests.front_mut() {
                    if req.opcode == AttOpcode::ExecuteWriteRequest {
                        let callback = req.callback.take().ok_or(AttError::InvalidState)?;
                        callback(Ok(Vec::new()))?; // Success, no data
                        requests.pop_front();
                        Ok(())
                    } else {
                        warn!(
                            "Received ExecuteWriteResponse for non-execute-write request: {:?}",
                            req.opcode
                        );
                        Err(AttError::UnexpectedResponse)
                    }
                } else {
                    warn!("Received ExecuteWriteResponse with no pending request");
                    Err(AttError::UnexpectedResponse)
                }
            }
            Ok(AttOpcode::HandleValueNotification) => {
                if pdu.len() < 3 {
                    // Opcode + Handle (2) + Value (at least 0)
                    return Err(AttError::InvalidPdu);
                }
                let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
                let value = &pdu[3..];
                info!(
                    "Received Notification: Handle=0x{:04X}, Value={:?}",
                    handle, value
                );
                let callbacks = self.notification_callbacks.lock().unwrap();
                if let Some(callback) = callbacks.get(&handle) {
                    callback(value.to_vec()); // Call the registered callback
                }
                Ok(())
            }
            Ok(AttOpcode::HandleValueIndication) => {
                if pdu.len() < 3 {
                    return Err(AttError::InvalidPdu);
                }
                let handle = u16::from_le_bytes([pdu[1], pdu[2]]);
                let value = &pdu[3..];
                info!(
                    "Received Indication: Handle=0x{:04X}, Value={:?}",
                    handle, value
                );
                let callbacks = self.indication_callbacks.lock().unwrap();
                if let Some(callback) = callbacks.get(&handle) {
                    callback(value.to_vec()); // Call the registered callback
                }
                // Send confirmation
                // Need access to att_client or send_att_pdu method
                // self.send_att_pdu(&[AttOpcode::HandleValueConfirmation as u8])?;
                Ok(())
            }
            Ok(AttOpcode::ErrorResponse) => {
                // Parse ErrorResponse
                if data.len() < 4 {
                    return Err(AttError::InvalidPdu);
                }
                let req_opcode_byte = data[0];
                let handle = u16::from_le_bytes([data[1], data[2]]);
                let error_code_byte = data[3];
                let error_code = AttErrorCode::from(error_code_byte);
                error!(
                    "ATT Error Response: ReqOpcode=0x{:02X}, Handle=0x{:04X}, ErrorCode={:?}",
                    req_opcode_byte, handle, error_code
                );

                // Find pending request and complete it with error
                let mut requests = self.pending_requests.lock().unwrap();
                if let Some(req) = requests.front_mut() {
                    // Check if the req_opcode matches the pending request
                    if req.opcode as u8 == req_opcode_byte {
                        let callback = req.callback.take().ok_or(AttError::InvalidState)?;
                        callback(Err(AttError::Protocol(error_code, handle)))?;
                        requests.pop_front();
                    } else {
                        warn!("Received ErrorResponse for opcode 0x{:02X}, but pending request is {:?}", req_opcode_byte, req.opcode);
                        // Don't remove the pending request, maybe the error is for something else?
                    }
                } else {
                    warn!("Received ErrorResponse with no pending request");
                }
                // Propagate the error if needed, or just log it?
                Err(AttError::Protocol(error_code, handle))
            }
            Ok(unhandled_opcode) => {
                warn!("Unhandled ATT Opcode received: {:?}", unhandled_opcode);
                let mut requests = self.pending_requests.lock().unwrap();
                if let Some(req) = requests.front_mut() {
                    if req.opcode != AttOpcode::ErrorResponse {
                        warn!(
                            "Received unexpected opcode {:?} while waiting for {:?}",
                            unhandled_opcode, req.opcode
                        );
                        let callback = req.callback.take().ok_or(AttError::InvalidState)?;
                        callback(Err(AttError::UnknownResponse("Unexpected opcode".into())))?;
                        requests.pop_front();
                    }
                }
                Err(AttError::UnsupportedOpcode(opcode_byte))
            }
            Err(_) => {
                error!("Invalid ATT Opcode received: 0x{:02X}", opcode_byte);
                let mut requests = self.pending_requests.lock().unwrap();
                if let Some(req) = requests.front_mut() {
                    let callback = req.callback.take().ok_or(AttError::InvalidState)?;
                    callback(Err(AttError::InvalidOpcode(opcode_byte)))?;
                    requests.pop_front();
                }
                Err(AttError::InvalidOpcode(opcode_byte))
            }
        }
    }

    fn advance_discovery_state(&mut self) -> AttResult<()> {
        let mut pending_discovery_guard = self.pending_discovery.lock().unwrap();
        let current_state = pending_discovery_guard.clone();

        match current_state {
            Some(DiscoveryState::DiscoveringServices(_)) => {
                let discovered_services = self.discovered_services.lock().unwrap();
                if !discovered_services.is_empty() {
                    *pending_discovery_guard = Some(DiscoveryState::DiscoveringCharacteristics(0));
                    let first_service = discovered_services[0].clone();
                    drop(discovered_services);
                    drop(pending_discovery_guard);
                } else {
                    *pending_discovery_guard = Some(DiscoveryState::Idle);
                    info!("Discovery complete (no services).");
                }
            }
            Some(DiscoveryState::DiscoveringCharacteristics(service_idx)) => {
                let discovered_services = self.discovered_services.lock().unwrap();
                let next_service_idx = service_idx + 1;
                if next_service_idx < discovered_services.len() {
                    *pending_discovery_guard =
                        Some(DiscoveryState::DiscoveringCharacteristics(next_service_idx));
                    let next_service = discovered_services[next_service_idx].clone();
                    drop(discovered_services);
                    drop(pending_discovery_guard);
                } else {
                    *pending_discovery_guard = Some(DiscoveryState::Idle);
                    info!("Discovery complete (all services).");
                }
            }
            _ => {}
        }
        Ok(())
    }
}
