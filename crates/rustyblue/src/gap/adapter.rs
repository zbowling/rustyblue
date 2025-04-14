use crate::error::{Error, HciError};
use crate::gap::constants::*;
use crate::gap::types::*;
use crate::hci::{HciCommand, HciEvent, HciSocket, LeAdvertisingReport};
use crate::scan::parse_advertising_data;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A callback function for device discovery
pub type DeviceDiscoveryCallback = Box<dyn Fn(&Device) + Send + 'static>;

/// GAP adapter for Bluetooth operations
pub struct GapAdapter {
    socket: HciSocket,
    devices: HashMap<BdAddr, Device>,
    discovery_callback: Option<DeviceDiscoveryCallback>,
    discovery_active: bool,
    local_name: Option<String>,
    local_address: Option<BdAddr>,
}

impl GapAdapter {
    /// Creates a new GAP adapter using the specified HCI device
    pub fn new(device_id: u16) -> Result<Self, Error> {
        let socket = HciSocket::open(device_id).map_err(Error::Hci)?;

        Ok(Self {
            socket,
            devices: HashMap::new(),
            discovery_callback: None,
            discovery_active: false,
            local_name: None,
            local_address: None,
        })
    }

    /// Sets the local device name
    pub fn set_local_name(&mut self, name: &str) -> Result<(), Error> {
        let mut params = Vec::new();

        // Add name bytes (up to 248 bytes)
        let name_bytes = name.as_bytes();
        let name_len = std::cmp::min(name_bytes.len(), 248);
        params.extend_from_slice(&name_bytes[0..name_len]);

        // Pad with zeros if necessary
        if name_len < 248 {
            params.resize(248, 0);
        }

        // Create and send HCI command
        let cmd = HciCommand::new(OGF_HOST_CTL, OCF_WRITE_LOCAL_NAME, params);
        self.socket.send_command(&cmd).map_err(Error::Hci)?;

        // Read command complete event
        let event = self.socket.read_event().map_err(Error::Hci)?;
        if event.is_command_complete(OGF_HOST_CTL, OCF_WRITE_LOCAL_NAME) {
            self.local_name = Some(name.to_string());
            Ok(())
        } else {
            Err(Error::ProtocolError("Failed to set local name".into()))
        }
    }

    /// Gets the local device name
    pub fn get_local_name(&mut self) -> Result<String, Error> {
        if let Some(name) = &self.local_name {
            return Ok(name.clone());
        }

        // Read the local name from the controller
        let cmd = HciCommand::new(OGF_HOST_CTL, OCF_READ_LOCAL_NAME, Vec::new());
        self.socket.send_command(&cmd).map_err(Error::Hci)?;

        // Read command complete event
        let event = self.socket.read_event().map_err(Error::Hci)?;
        if event.is_command_complete(OGF_HOST_CTL, OCF_READ_LOCAL_NAME) {
            if event.get_status() == 0 {
                let mut name = String::new();
                for &b in &event.get_parameters()[1..] {
                    if b == 0 {
                        break;
                    }
                    name.push(b as char);
                }
                self.local_name = Some(name.clone());
                Ok(name)
            } else {
                Err(Error::ProtocolError("Failed to get local name".into()))
            }
        } else {
            Err(Error::ProtocolError("Unexpected event received".into()))
        }
    }

    /// Gets the local device address
    pub fn get_local_address(&mut self) -> Result<BdAddr, Error> {
        if let Some(addr) = &self.local_address {
            return Ok(addr.clone());
        }

        // Read the local address from the controller
        let cmd = HciCommand::new(OGF_INFO_PARAM, OCF_READ_BD_ADDR, Vec::new());
        self.socket.send_command(&cmd).map_err(Error::Hci)?;

        // Read command complete event
        let event = self.socket.read_event().map_err(Error::Hci)?;
        if event.is_command_complete(OGF_INFO_PARAM, OCF_READ_BD_ADDR) {
            if event.get_status() == 0 {
                let params = event.get_parameters();
                if params.len() >= 7 {
                    let mut bytes = [0u8; 6];
                    bytes.copy_from_slice(&params[1..7]);
                    let addr = BdAddr::new(bytes);
                    self.local_address = Some(addr.clone());
                    Ok(addr)
                } else {
                    Err(Error::InvalidPacket("BD ADDR response too short".into()))
                }
            } else {
                Err(Error::ProtocolError("Failed to get BD ADDR".into()))
            }
        } else {
            Err(Error::ProtocolError("Unexpected event received".into()))
        }
    }

    /// Starts device discovery
    pub fn start_discovery(&mut self, callback: DeviceDiscoveryCallback) -> Result<(), Error> {
        if self.discovery_active {
            return Err(Error::ProtocolError("Discovery already active".into()));
        }

        // Set scan parameters
        let mut params = Vec::new();
        params.push(LE_SCAN_ACTIVE); // Active scanning
        params.extend_from_slice(&LE_SCAN_INTERVAL.to_le_bytes()); // Scan interval
        params.extend_from_slice(&LE_SCAN_WINDOW.to_le_bytes()); // Scan window
        params.push(0x00); // Own address type (public)
        params.push(0x00); // Filter policy (accept all)

        let cmd = HciCommand::new(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, params);
        self.socket.send_command(&cmd).map_err(Error::Hci)?;

        // Read command complete event
        let event = self.socket.read_event().map_err(Error::Hci)?;
        if !event.is_command_complete(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS)
            || event.get_status() != 0
        {
            return Err(Error::ProtocolError("Failed to set scan parameters".into()));
        }

        // Enable scanning
        params = Vec::new();
        params.push(0x01); // Enable scanning
        params.push(0x00); // Filter duplicates: disabled

        let cmd = HciCommand::new(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, params);
        self.socket.send_command(&cmd).map_err(Error::Hci)?;

        // Read command complete event
        let event = self.socket.read_event().map_err(Error::Hci)?;
        if !event.is_command_complete(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE) || event.get_status() != 0
        {
            return Err(Error::ProtocolError("Failed to enable scanning".into()));
        }

        self.discovery_callback = Some(callback);
        self.discovery_active = true;

        Ok(())
    }

    /// Stops device discovery
    pub fn stop_discovery(&mut self) -> Result<(), Error> {
        if !self.discovery_active {
            return Ok(());
        }

        // Disable scanning
        let mut params = Vec::new();
        params.push(0x00); // Disable scanning
        params.push(0x00); // Filter duplicates: disabled

        let cmd = HciCommand::new(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, params);
        self.socket.send_command(&cmd).map_err(Error::Hci)?;

        // Read command complete event
        let event = self.socket.read_event().map_err(Error::Hci)?;
        if !event.is_command_complete(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE) || event.get_status() != 0
        {
            return Err(Error::ProtocolError("Failed to disable scanning".into()));
        }

        self.discovery_callback = None;
        self.discovery_active = false;

        Ok(())
    }

    /// Connects to a device
    pub fn connect(&mut self, address: &BdAddr, address_type: AddressType) -> Result<(), Error> {
        let mut params = Vec::new();

        // Set connection parameters
        params.extend_from_slice(&LE_CONN_INTERVAL_MIN.to_le_bytes());
        params.extend_from_slice(&LE_CONN_INTERVAL_MAX.to_le_bytes());
        params.extend_from_slice(&LE_CONN_LATENCY.to_le_bytes());
        params.extend_from_slice(&LE_SUPERVISION_TIMEOUT.to_le_bytes());
        params.extend_from_slice(&LE_MIN_CE_LENGTH.to_le_bytes());
        params.extend_from_slice(&LE_MAX_CE_LENGTH.to_le_bytes());

        let cmd = HciCommand::new(OGF_LE_CTL, OCF_LE_SET_CONNECTION_PARAMETERS, params);
        self.socket.send_command(&cmd).map_err(Error::Hci)?;

        // Read command complete event
        let event = self.socket.read_event().map_err(Error::Hci)?;
        if !event.is_command_complete(OGF_LE_CTL, OCF_LE_SET_CONNECTION_PARAMETERS)
            || event.get_status() != 0
        {
            return Err(Error::ProtocolError(
                "Failed to set connection parameters".into(),
            ));
        }

        // Create connection
        params = Vec::new();
        params.extend_from_slice(&LE_SCAN_INTERVAL.to_le_bytes());
        params.extend_from_slice(&LE_SCAN_WINDOW.to_le_bytes());
        params.push(0x00); // Filter policy
        params.push(u8::from(address_type)); // Peer address type
        params.extend_from_slice(address.as_slice()); // Peer address
        params.push(0x00); // Own address type

        let cmd = HciCommand::new(OGF_LE_CTL, OCF_LE_CREATE_CONNECTION, params);
        self.socket.send_command(&cmd).map_err(Error::Hci)?;

        // The connection complete event will be received asynchronously

        Ok(())
    }

    /// Disconnects from a device
    pub fn disconnect(&mut self, handle: u16, reason: u8) -> Result<(), Error> {
        let mut params = Vec::new();
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(reason);

        let cmd = HciCommand::new(OGF_LINK_CTL, OCF_DISCONNECT, params);
        self.socket.send_command(&cmd).map_err(Error::Hci)?;

        // The disconnection complete event will be received asynchronously

        Ok(())
    }

    /// Process incoming HCI events
    pub fn process_events(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        let start_time = Instant::now();

        loop {
            // Check timeout
            if let Some(timeout) = timeout {
                if start_time.elapsed() >= timeout {
                    break;
                }
            }

            // Read event with remaining timeout
            let remaining_timeout = timeout.map(|t| {
                let elapsed = start_time.elapsed();
                if elapsed < t {
                    t - elapsed
                } else {
                    Duration::from_millis(0)
                }
            });

            let event_result = self
                .socket
                .read_event_timeout(remaining_timeout)
                .map_err(Error::Hci);

            // Handle timeout
            if let Err(Error::Hci(HciError::ReceiveError(e))) = &event_result {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    break;
                }
            }

            // Process event
            if let Ok(event) = event_result {
                self.handle_event(event)?;
            } else if let Err(e) = event_result {
                return Err(e);
            }
        }

        Ok(())
    }

    /// Handle HCI events
    fn handle_event(&mut self, event: HciEvent) -> Result<(), Error> {
        match event.get_event_code() {
            EVT_LE_META_EVENT => {
                let subevent = event.get_parameters()[0];
                match subevent {
                    EVT_LE_ADVERTISING_REPORT => {
                        self.handle_advertising_report(&event)?;
                    }
                    EVT_LE_CONNECTION_COMPLETE => {
                        // Handle connection complete
                    }
                    EVT_LE_DISCONNECTION_COMPLETE => {
                        // Handle disconnection complete
                    }
                    _ => {
                        // Ignore other LE meta events
                    }
                }
            }
            _ => {
                // Ignore other events
            }
        }

        Ok(())
    }

    /// Handle LE advertising reports
    fn handle_advertising_report(&mut self, event: &HciEvent) -> Result<(), Error> {
        if !self.discovery_active {
            return Ok(());
        }

        let reports = LeAdvertisingReport::parse_from_event(event)?;

        for report in reports {
            let addr = BdAddr::from_slice(&report.address).unwrap();
            let addr_type = AddressType::from(report.address_type);

            // Update or create device
            let device = self
                .devices
                .entry(addr.clone())
                .or_insert_with(|| Device::new(addr.clone(), addr_type));

            // Update RSSI
            device.rssi = Some(report.rssi);

            // Parse advertising data
            if !report.data.is_empty() {
                let ad_data = parse_advertising_data(&report.data);

                for (data_type, data) in ad_data {
                    match data_type {
                        ADV_TYPE_SHORT_LOCAL_NAME | ADV_TYPE_COMPLETE_LOCAL_NAME => {
                            if let Ok(name) = String::from_utf8(data.to_vec()) {
                                device.name = Some(name);
                            }
                        }
                        ADV_TYPE_TX_POWER_LEVEL => {
                            if data.len() == 1 {
                                device.tx_power = Some(data[0] as i8);
                            }
                        }
                        ADV_TYPE_MANUFACTURER_SPECIFIC => {
                            device.manufacturer_data = Some(data.to_vec());
                        }
                        ADV_TYPE_FLAGS => {
                            if data.len() == 1 {
                                device.flags = Some(data[0]);
                            }
                        }
                        ADV_TYPE_APPEARANCE => {
                            if data.len() == 2 {
                                device.appearance = Some(u16::from_le_bytes([data[0], data[1]]));
                            }
                        }
                        // TODO: Handle more data types like service UUIDs
                        _ => {}
                    }
                }
            }

            // Call discovery callback
            if let Some(callback) = &self.discovery_callback {
                callback(device);
            }
        }

        Ok(())
    }
}
