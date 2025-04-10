//! ATT Server implementation
use super::error::{AttError, AttErrorCode, AttResult};
use super::types::*;
use super::constants::*;
use super::database::{AttributeDatabase, Attribute};
use crate::gap::BdAddr;
use crate::gatt::Uuid;
use crate::l2cap::{L2capManager, L2capError, ConnectionType};
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;

/// Client connection information
struct ClientConnection {
    /// BD address
    addr: BdAddr,
    /// L2CAP channel ID
    channel_id: u16,
    /// MTU size
    mtu: u16,
    /// Security level
    security_level: SecurityLevel,
}

/// ATT Server
pub struct AttServer {
    /// L2CAP manager
    l2cap_manager: Arc<L2capManager>,
    /// Attribute database
    database: Arc<AttributeDatabase>,
    /// Server configuration
    config: RwLock<AttServerConfig>,
    /// Connected clients
    clients: RwLock<HashMap<BdAddr, ClientConnection>>,
    /// Prepared writes
    prepared_writes: RwLock<HashMap<BdAddr, Vec<PrepareWriteRequest>>>,
}

/// ATT Server configuration
#[derive(Debug, Clone)]
pub struct AttServerConfig {
    /// Server MTU
    pub mtu: u16,
    /// Security level
    pub security_level: SecurityLevel,
}

impl Default for AttServerConfig {
    fn default() -> Self {
        Self {
            mtu: ATT_DEFAULT_MTU,
            security_level: SecurityLevel::None,
        }
    }
}

impl AttServer {
    /// Create a new ATT server
    pub fn new(l2cap_manager: Arc<L2capManager>, database: Arc<AttributeDatabase>) -> Self {
        Self {
            l2cap_manager,
            database,
            config: RwLock::new(AttServerConfig::default()),
            clients: RwLock::new(HashMap::new()),
            prepared_writes: RwLock::new(HashMap::new()),
        }
    }
    
    /// Set server configuration
    pub fn set_config(&self, config: AttServerConfig) {
        let mut server_config = self.config.write().unwrap();
        *server_config = config;
    }
    
    /// Get server configuration
    pub fn config(&self) -> AttServerConfig {
        self.config.read().unwrap().clone()
    }
    
    /// Start the server
    pub fn start(&self) -> AttResult<()> {
        // Register for the ATT fixed channel
        self.l2cap_manager.register_fixed_channel_callback(
            ATT_CID,
            move |remote_addr: BdAddr, data: &[u8]| -> Result<(), L2capError> {
                // Handle incoming ATT data
                // In a real implementation, this would dispatch to the ATT server
                println!("Received ATT data from {}: {:?}", remote_addr, data);
                Ok(())
            }
        ).map_err(|e| AttError::from(e))?;
        
        Ok(())
    }
    
    /// Stop the server
    pub fn stop(&self) -> AttResult<()> {
        // Unregister from the ATT fixed channel
        self.l2cap_manager.unregister_fixed_channel_callback(ATT_CID)
            .map_err(|e| AttError::from(e))?;
        
        // Disconnect all clients
        let clients = self.clients.read().unwrap().clone();
        for (addr, client) in clients {
            self.disconnect_client(addr)?;
        }
        
        Ok(())
    }
    
    /// Accept a client connection
    pub fn accept_client(&self, addr: BdAddr, channel_id: u16) -> AttResult<()> {
        // Check if client is already connected
        let mut clients = self.clients.write().unwrap();
        if clients.contains_key(&addr) {
            return Err(AttError::InvalidState);
        }
        
        // Create new client connection
        let client = ClientConnection {
            addr,
            channel_id,
            mtu: ATT_DEFAULT_MTU,
            security_level: SecurityLevel::None,
        };
        
        // Add to connected clients
        clients.insert(addr, client);
        
        Ok(())
    }
    
    /// Disconnect a client
    pub fn disconnect_client(&self, addr: BdAddr) -> AttResult<()> {
        // Remove client from connected clients
        let client = {
            let mut clients = self.clients.write().unwrap();
            clients.remove(&addr).ok_or(AttError::InvalidState)?
        };
        
        // Clear any prepared writes
        {
            let mut prepared_writes = self.prepared_writes.write().unwrap();
            prepared_writes.remove(&addr);
        }
        
        // Disconnect L2CAP channel
        self.l2cap_manager.disconnect(client.channel_id)
            .map_err(|e| AttError::from(e))?;
        
        Ok(())
    }
    
    /// Set client security level
    pub fn set_client_security_level(&self, addr: BdAddr, level: SecurityLevel) -> AttResult<()> {
        let mut clients = self.clients.write().unwrap();
        let client = clients.get_mut(&addr).ok_or(AttError::InvalidState)?;
        client.security_level = level;
        
        Ok(())
    }
    
    /// Get client security level
    pub fn client_security_level(&self, addr: BdAddr) -> AttResult<SecurityLevel> {
        let clients = self.clients.read().unwrap();
        let client = clients.get(&addr).ok_or(AttError::InvalidState)?;
        
        Ok(client.security_level)
    }
    
    /// Send a notification to a client
    pub fn send_notification(
        &self,
        addr: BdAddr,
        handle: u16,
        value: &[u8]
    ) -> AttResult<()> {
        // Check if client is connected
        let clients = self.clients.read().unwrap();
        let client = clients.get(&addr).ok_or(AttError::InvalidState)?;
        
        // Check value length against MTU
        if value.len() > (client.mtu as usize - 3) {
            return Err(AttError::InvalidAttributeValueLength);
        }
        
        // Create notification
        let notification = HandleValueNotification {
            handle,
            value: value.to_vec(),
        };
        
        // Send notification
        let data = notification.serialize();
        self.l2cap_manager.send_data(client.channel_id, &data)
            .map_err(|e| AttError::from(e))?;
        
        Ok(())
    }
    
    /// Send an indication to a client
    pub fn send_indication(
        &self,
        addr: BdAddr,
        handle: u16,
        value: &[u8]
    ) -> AttResult<()> {
        // Check if client is connected
        let clients = self.clients.read().unwrap();
        let client = clients.get(&addr).ok_or(AttError::InvalidState)?;
        
        // Check value length against MTU
        if value.len() > (client.mtu as usize - 3) {
            return Err(AttError::InvalidAttributeValueLength);
        }
        
        // Create indication
        let indication = HandleValueIndication {
            handle,
            value: value.to_vec(),
        };
        
        // Send indication
        let data = indication.serialize();
        self.l2cap_manager.send_data(client.channel_id, &data)
            .map_err(|e| AttError::from(e))?;
        
        // Wait for confirmation
        // In a real implementation, we would wait for a confirmation
        // and potentially retry or timeout
        
        Ok(())
    }
    
    /// Handle a received ATT PDU
    pub fn handle_att_pdu(&self, addr: BdAddr, data: &[u8]) -> AttResult<()> {
        if data.is_empty() {
            return Err(AttError::InvalidPdu);
        }
        
        // Check if client is connected
        let clients = self.clients.read().unwrap();
        let client = clients.get(&addr).ok_or(AttError::InvalidState)?;
        let channel_id = client.channel_id;
        let security_level = client.security_level;
        drop(clients); // Release lock
        
        // Parse opcode
        let opcode = data[0];
        
        // Handle the PDU based on opcode
        match opcode {
            ATT_EXCHANGE_MTU_REQ => {
                self.handle_exchange_mtu_request(addr, data, channel_id)
            },
            ATT_FIND_INFO_REQ => {
                self.handle_find_information_request(addr, data, channel_id, security_level)
            },
            ATT_FIND_BY_TYPE_VALUE_REQ => {
                self.handle_find_by_type_value_request(addr, data, channel_id, security_level)
            },
            ATT_READ_BY_TYPE_REQ => {
                self.handle_read_by_type_request(addr, data, channel_id, security_level)
            },
            ATT_READ_REQ => {
                self.handle_read_request(addr, data, channel_id, security_level)
            },
            ATT_READ_BLOB_REQ => {
                self.handle_read_blob_request(addr, data, channel_id, security_level)
            },
            ATT_READ_MULTIPLE_REQ => {
                self.handle_read_multiple_request(addr, data, channel_id, security_level)
            },
            ATT_READ_BY_GROUP_TYPE_REQ => {
                self.handle_read_by_group_type_request(addr, data, channel_id, security_level)
            },
            ATT_WRITE_REQ => {
                self.handle_write_request(addr, data, channel_id, security_level)
            },
            ATT_WRITE_CMD => {
                self.handle_write_command(addr, data, security_level)
            },
            ATT_PREPARE_WRITE_REQ => {
                self.handle_prepare_write_request(addr, data, channel_id, security_level)
            },
            ATT_EXECUTE_WRITE_REQ => {
                self.handle_execute_write_request(addr, data, channel_id, security_level)
            },
            ATT_HANDLE_VALUE_CONF => {
                self.handle_handle_value_confirmation(addr)
            },
            _ => {
                // Unknown or unsupported opcode
                self.send_error_response(
                    channel_id,
                    opcode,
                    0,
                    AttErrorCode::RequestNotSupported
                )
            }
        }
    }
    
    /// Handle Exchange MTU Request
    fn handle_exchange_mtu_request(
        &self,
        addr: BdAddr,
        data: &[u8],
        channel_id: u16
    ) -> AttResult<()> {
        // Parse request
        let request = match ExchangeMtuRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_EXCHANGE_MTU_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Get our server MTU
        let server_mtu = self.config().mtu;
        
        // Update client MTU
        {
            let mut clients = self.clients.write().unwrap();
            if let Some(client) = clients.get_mut(&addr) {
                client.mtu = std::cmp::min(request.client_mtu, server_mtu);
            }
        }
        
        // Send response
        let response = ExchangeMtuResponse { server_mtu };
        let response_data = response.serialize();
        
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Find Information Request
    fn handle_find_information_request(
        &self,
        _addr: BdAddr,
        data: &[u8],
        channel_id: u16,
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse request
        let request = match FindInformationRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_FIND_INFO_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Validate handles
        if request.start_handle > request.end_handle {
            return self.send_error_response(
                channel_id,
                ATT_FIND_INFO_REQ,
                request.start_handle,
                AttErrorCode::InvalidHandle
            );
        }
        
        // Get attribute information
        let info = match self.database.find_information(
            request.start_handle,
            request.end_handle,
            security_level
        ) {
            Ok(info) => info,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_FIND_INFO_REQ,
                request.start_handle,
                e.to_error_code()
            ),
        };
        
        // Check if any attributes were found
        if info.is_empty() {
            return self.send_error_response(
                channel_id,
                ATT_FIND_INFO_REQ,
                request.start_handle,
                AttErrorCode::AttributeNotFound
            );
        }
        
        // Determine format (16-bit or 128-bit UUIDs)
        let format = if info.iter().all(|(_, uuid)| uuid.as_u16().is_some()) {
            ATT_FIND_INFO_RSP_FORMAT_16BIT
        } else {
            ATT_FIND_INFO_RSP_FORMAT_128BIT
        };
        
        // Create response data
        let mut handle_uuid_pairs = Vec::new();
        for (handle, uuid) in info {
            if format == ATT_FIND_INFO_RSP_FORMAT_16BIT {
                if let Some(uuid16) = uuid.as_u16() {
                    handle_uuid_pairs.push(HandleUuidPair::Uuid16(handle, uuid16));
                }
            } else {
                handle_uuid_pairs.push(HandleUuidPair::Uuid128(handle, uuid));
            }
        }
        
        // Create response
        let response = FindInformationResponse {
            format,
            information_data: handle_uuid_pairs,
        };
        
        // Send response
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Find By Type Value Request
    fn handle_find_by_type_value_request(
        &self,
        addr: BdAddr,
        data: &[u8],
        channel_id: u16,
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse request
        let request = match FindByTypeValueRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_FIND_BY_TYPE_VALUE_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Validate handles
        if request.start_handle > request.end_handle {
            return self.send_error_response(
                channel_id,
                ATT_FIND_BY_TYPE_VALUE_REQ,
                request.start_handle,
                AttErrorCode::InvalidHandle
            );
        }
        
        // Find attributes by type and value
        let type_uuid = Uuid::from_u16(request.attribute_type);
        let handles = match self.database.find_by_type_value(
            request.start_handle,
            request.end_handle,
            &type_uuid,
            &request.attribute_value,
            security_level
        ) {
            Ok(handles) => handles,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_FIND_BY_TYPE_VALUE_REQ,
                request.start_handle,
                e.to_error_code()
            ),
        };
        
        // Check if any attributes were found
        if handles.is_empty() {
            return self.send_error_response(
                channel_id,
                ATT_FIND_BY_TYPE_VALUE_REQ,
                request.start_handle,
                AttErrorCode::AttributeNotFound
            );
        }
        
        // Create response data
        let mut handle_ranges = Vec::new();
        for (found_handle, group_end_handle) in handles {
            handle_ranges.push(HandleRange {
                found_handle,
                group_end_handle,
            });
        }
        
        // Create response
        let response = FindByTypeValueResponse {
            handles: handle_ranges,
        };
        
        // Send response
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Read By Type Request
    fn handle_read_by_type_request(
        &self,
        addr: BdAddr,
        data: &[u8],
        channel_id: u16,
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse request
        let request = match ReadByTypeRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_READ_BY_TYPE_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Validate handles
        if request.start_handle > request.end_handle {
            return self.send_error_response(
                channel_id,
                ATT_READ_BY_TYPE_REQ,
                request.start_handle,
                AttErrorCode::InvalidHandle
            );
        }
        
        // Read attributes by type
        let attributes = match self.database.read_by_type(
            request.start_handle,
            request.end_handle,
            &request.attribute_type,
            security_level
        ) {
            Ok(attrs) => attrs,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_READ_BY_TYPE_REQ,
                request.start_handle,
                e.to_error_code()
            ),
        };
        
        // Check if any attributes were found
        if attributes.is_empty() {
            return self.send_error_response(
                channel_id,
                ATT_READ_BY_TYPE_REQ,
                request.start_handle,
                AttErrorCode::AttributeNotFound
            );
        }
        
        // Get client MTU
        let clients = self.clients.read().unwrap();
        let client = clients.get(&addr).ok_or(AttError::InvalidState)?;
        let _mtu = client.mtu;
        
        // Determine length (must be the same for all entries)
        let mut length = 2 + attributes[0].1.len(); // handle(2) + value
        for (_, value) in &attributes {
            if 2 + value.len() != length {
                // Different lengths, truncate all to shortest
                length = std::cmp::min(length, 2 + value.len());
            }
        }
        
        // Create response data
        let mut data_list = Vec::new();
        for (handle, value) in attributes {
            let value_len = length - 2;
            let mut attr_value = value;
            if attr_value.len() > value_len {
                attr_value.truncate(value_len);
            }
            
            data_list.push(HandleValue {
                handle,
                value: attr_value,
            });
        }
        
        // Create response
        let response = ReadByTypeResponse {
            length: length as u8,
            data: data_list,
        };
        
        // Send response
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Read Request
    fn handle_read_request(
        &self,
        addr: BdAddr,
        data: &[u8],
        channel_id: u16,
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse request
        let request = match ReadRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_READ_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Read attribute
        let value = match self.database.read_by_handle(request.handle, security_level) {
            Ok(value) => value,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_READ_REQ,
                request.handle,
                e.to_error_code()
            ),
        };
        
        // Get client MTU
        let clients = self.clients.read().unwrap();
        let client = clients.get(&addr).ok_or(AttError::InvalidState)?;
        let _mtu = client.mtu;
        
        // Truncate value if larger than MTU - 1
        let max_len = client.mtu as usize - 1;
        let value = if value.len() > max_len {
            value[..max_len].to_vec()
        } else {
            value
        };
        
        // Create response
        let response = ReadResponse { value };
        
        // Send response
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Read Blob Request
    fn handle_read_blob_request(
        &self,
        addr: BdAddr,
        data: &[u8],
        channel_id: u16,
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse request
        let request = match ReadBlobRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_READ_BLOB_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Read blob
        let value = match self.database.read_blob_by_handle(
            request.handle,
            request.offset,
            security_level
        ) {
            Ok(value) => value,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_READ_BLOB_REQ,
                request.handle,
                e.to_error_code()
            ),
        };
        
        // Get client MTU
        let clients = self.clients.read().unwrap();
        let client = clients.get(&addr).ok_or(AttError::InvalidState)?;
        let _mtu = client.mtu;
        
        // Truncate value if larger than MTU - 1
        let max_len = client.mtu as usize - 1;
        let value = if value.len() > max_len {
            value[..max_len].to_vec()
        } else {
            value
        };
        
        // Create response
        let response = ReadBlobResponse { value };
        
        // Send response
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Read Multiple Request
    fn handle_read_multiple_request(
        &self,
        addr: BdAddr,
        data: &[u8],
        channel_id: u16,
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse request
        let request = match ReadMultipleRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_READ_MULTIPLE_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Read multiple attributes
        let values = match self.database.read_multiple(&request.handles, security_level) {
            Ok(values) => values,
            Err(e) => {
                // Find the handle that caused the error
                for &handle in &request.handles {
                    if let Err(_) = self.database.read_by_handle(handle, security_level) {
                        return self.send_error_response(
                            channel_id,
                            ATT_READ_MULTIPLE_REQ,
                            handle,
                            e.to_error_code()
                        );
                    }
                }
                
                // If we can't determine which handle caused the error, use the first one
                return self.send_error_response(
                    channel_id,
                    ATT_READ_MULTIPLE_REQ,
                    request.handles[0],
                    e.to_error_code()
                );
            }
        };
        
        // Get client MTU
        let clients = self.clients.read().unwrap();
        let client = clients.get(&addr).ok_or(AttError::InvalidState)?;
        let _mtu = client.mtu;
        
        // Truncate values if larger than MTU - 1
        let max_len = client.mtu as usize - 1;
        let values = if values.len() > max_len {
            values[..max_len].to_vec()
        } else {
            values
        };
        
        // Create response
        let response = ReadMultipleResponse { values };
        
        // Send response
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Read By Group Type Request
    fn handle_read_by_group_type_request(
        &self,
        addr: BdAddr,
        data: &[u8],
        channel_id: u16,
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse request
        let request = match ReadByGroupTypeRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_READ_BY_GROUP_TYPE_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Validate handles
        if request.start_handle > request.end_handle {
            return self.send_error_response(
                channel_id,
                ATT_READ_BY_GROUP_TYPE_REQ,
                request.start_handle,
                AttErrorCode::InvalidHandle
            );
        }
        
        // Check if group type is allowed
        if request.group_type != Uuid::from_u16(PRIMARY_SERVICE_UUID) &&
           request.group_type != Uuid::from_u16(SECONDARY_SERVICE_UUID) {
            return self.send_error_response(
                channel_id,
                ATT_READ_BY_GROUP_TYPE_REQ,
                request.start_handle,
                AttErrorCode::UnsupportedGroupType
            );
        }
        
        // Get group handles
        let groups = match self.database.get_group_handles(
            request.start_handle,
            request.end_handle,
            &request.group_type,
            security_level
        ) {
            Ok(groups) => groups,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_READ_BY_GROUP_TYPE_REQ,
                request.start_handle,
                e.to_error_code()
            ),
        };
        
        // Check if any groups were found
        if groups.is_empty() {
            return self.send_error_response(
                channel_id,
                ATT_READ_BY_GROUP_TYPE_REQ,
                request.start_handle,
                AttErrorCode::AttributeNotFound
            );
        }
        
        // Get client MTU
        let clients = self.clients.read().unwrap();
        let client = clients.get(&addr).ok_or(AttError::InvalidState)?;
        let _mtu = client.mtu;
        
        // Determine length (must be the same for all entries)
        // Length = handle (2) + end group handle (2) + value
        let first_value_len = groups[0].2.len();
        let length = 4 + first_value_len;
        
        // Create response data
        let mut data_list = Vec::new();
        for (handle, end_handle, value) in groups {
            // Only include attributes with the same value length
            if value.len() == first_value_len {
                data_list.push(AttributeData {
                    handle,
                    end_group_handle: end_handle,
                    value,
                });
            }
        }
        
        // Create response
        let response = ReadByGroupTypeResponse {
            length: length as u8,
            data: data_list,
        };
        
        // Send response
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Write Request
    fn handle_write_request(
        &self,
        addr: BdAddr,
        data: &[u8],
        channel_id: u16,
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse request
        let request = match WriteRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_WRITE_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Write to attribute
        match self.database.write_by_handle(request.handle, &request.value, security_level) {
            Ok(_) => {},
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_WRITE_REQ,
                request.handle,
                e.to_error_code()
            ),
        }
        
        // Send response
        let response = WriteResponse;
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Write Command
    fn handle_write_command(
        &self,
        addr: BdAddr,
        data: &[u8],
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse command
        let command = match WriteCommand::parse(data) {
            Ok(cmd) => cmd,
            Err(_) => return Ok(()), // Ignore invalid commands
        };
        
        // Write to attribute (ignore errors)
        let _ = self.database.write_by_handle(command.handle, &command.value, security_level);
        
        // No response for write commands
        Ok(())
    }
    
    /// Handle Prepare Write Request
    fn handle_prepare_write_request(
        &self,
        addr: BdAddr,
        data: &[u8],
        channel_id: u16,
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse request
        let request = match PrepareWriteRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_PREPARE_WRITE_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Check if attribute exists and is writable
        let attr = match self.database.get_attribute(request.handle) {
            Ok(attr) => attr,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_PREPARE_WRITE_REQ,
                request.handle,
                e.to_error_code()
            ),
        };
        
        if !attr.can_write(security_level) {
            return self.send_error_response(
                channel_id,
                ATT_PREPARE_WRITE_REQ,
                request.handle,
                AttErrorCode::WriteNotPermitted
            );
        }
        
        // Store the prepared write
        {
            let mut prepared_writes = self.prepared_writes.write().unwrap();
            let client_writes = prepared_writes.entry(addr).or_insert_with(Vec::new);
            
            // Check queue size
            if client_writes.len() >= ATT_PREPARE_WRITE_QUEUE_SIZE {
                return self.send_error_response(
                    channel_id,
                    ATT_PREPARE_WRITE_REQ,
                    request.handle,
                    AttErrorCode::PrepareQueueFull
                );
            }
            
            // Add to queue
            client_writes.push(request.clone());
        }
        
        // Send response
        let response = PrepareWriteResponse {
            handle: request.handle,
            offset: request.offset,
            value: request.value,
        };
        
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Execute Write Request
    fn handle_execute_write_request(
        &self,
        addr: BdAddr,
        data: &[u8],
        channel_id: u16,
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Parse request
        let request = match ExecuteWriteRequest::parse(data) {
            Ok(req) => req,
            Err(e) => return self.send_error_response(
                channel_id,
                ATT_EXECUTE_WRITE_REQ,
                0,
                e.to_error_code()
            ),
        };
        
        // Get prepared writes
        let prepared_writes = {
            let mut all_prepared_writes = self.prepared_writes.write().unwrap();
            all_prepared_writes.remove(&addr).unwrap_or_default()
        };
        
        // Execute or cancel
        if request.flags == ATT_EXEC_WRITE_COMMIT {
            // Execute writes
            let mut attribute_values = HashMap::new();
            
            // Collect values by handle
            for write in &prepared_writes {
                let entry = attribute_values.entry(write.handle).or_insert_with(Vec::new);
                entry.push((write.offset, write.value.clone()));
            }
            
            // Execute writes for each handle
            for (handle, parts) in attribute_values {
                // Sort by offset
                let mut sorted_parts = parts;
                sorted_parts.sort_by_key(|(offset, _)| *offset);
                
                // Check if parts are contiguous
                let mut expected_offset = 0;
                for (offset, part) in &sorted_parts {
                    if *offset != expected_offset {
                        return self.send_error_response(
                            channel_id,
                            ATT_EXECUTE_WRITE_REQ,
                            handle,
                            AttErrorCode::InvalidOffset
                        );
                    }
                    expected_offset = *offset + part.len() as u16;
                }
                
                // Combine parts
                let mut combined_value = Vec::new();
                for (_, part) in sorted_parts {
                    combined_value.extend_from_slice(&part);
                }
                
                // Write to attribute
                match self.database.write_by_handle(handle, &combined_value, security_level) {
                    Ok(_) => {},
                    Err(e) => return self.send_error_response(
                        channel_id,
                        ATT_EXECUTE_WRITE_REQ,
                        handle,
                        e.to_error_code()
                    ),
                }
            }
        }
        
        // Send response
        let response = ExecuteWriteResponse;
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
    
    /// Handle Handle Value Confirmation
    fn handle_handle_value_confirmation(
        &self,
        addr: BdAddr
    ) -> AttResult<()> {
        // Process indication confirmation
        // In a real implementation, this would release any pending indication
        
        Ok(())
    }
    
    /// Send an error response
    fn send_error_response(
        &self,
        channel_id: u16,
        request_opcode: u8,
        handle: u16,
        error_code: AttErrorCode
    ) -> AttResult<()> {
        // Create error response
        let response = ErrorResponse {
            request_opcode,
            handle,
            error_code,
        };
        
        // Send response
        let response_data = response.serialize();
        self.l2cap_manager.send_data(channel_id, &response_data)
            .map_err(|e| AttError::from(e))
    }
}