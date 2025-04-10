//! ATT Client implementation
use super::error::{AttError, AttErrorCode, AttResult};
use super::types::*;
use super::constants::*;
use crate::gap::BdAddr;
use crate::gatt::Uuid;
use crate::l2cap::{L2capManager, L2capError, ConnectionType};
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Value notification callback
pub type NotificationCallback = Arc<Mutex<dyn FnMut(u16, &[u8]) -> AttResult<()> + Send + Sync>>;

/// Indication callback
pub type IndicationCallback = Arc<Mutex<dyn FnMut(u16, &[u8]) -> AttResult<()> + Send + Sync>>;

/// Transaction timeout (ms)
const ATT_TRANSACTION_TIMEOUT: u64 = 30000;

/// ATT Transaction
struct AttTransaction {
    /// Transaction opcode
    opcode: u8,
    /// Response data
    response: Option<Vec<u8>>,
    /// Transaction start time
    start_time: Instant,
    /// Error
    error: Option<AttError>,
}

/// ATT Client
pub struct AttClient {
    /// Remote device address
    remote_addr: BdAddr,
    /// L2CAP manager
    l2cap_manager: Arc<L2capManager>,
    /// L2CAP channel ID
    channel_id: RwLock<Option<u16>>,
    /// Client MTU
    client_mtu: RwLock<u16>,
    /// Server MTU
    server_mtu: RwLock<u16>,
    /// Pending transactions
    transactions: RwLock<HashMap<u8, AttTransaction>>,
    /// Notification callback
    notification_callback: RwLock<Option<NotificationCallback>>,
    /// Indication callback
    indication_callback: RwLock<Option<IndicationCallback>>,
    /// Whether the client is connected
    connected: RwLock<bool>,
}

impl AttClient {
    /// Create a new ATT client
    pub fn new(remote_addr: BdAddr, l2cap_manager: Arc<L2capManager>) -> Self {
        Self {
            remote_addr,
            l2cap_manager,
            channel_id: RwLock::new(None),
            client_mtu: RwLock::new(ATT_DEFAULT_MTU),
            server_mtu: RwLock::new(ATT_DEFAULT_MTU),
            transactions: RwLock::new(HashMap::new()),
            notification_callback: RwLock::new(None),
            indication_callback: RwLock::new(None),
            connected: RwLock::new(false),
        }
    }
    
    /// Connect to the ATT server
    pub fn connect(&self, hci_handle: u16) -> AttResult<()> {
        // Check if already connected
        if *self.connected.read().unwrap() {
            return Ok(());
        }
        
        // Connect L2CAP channel for ATT
        let channel_id = match self.l2cap_manager.connect_fixed_channel(ATT_CID, hci_handle) {
            Ok(cid) => cid,
            Err(e) => return Err(AttError::from(e)),
        };
        
        // Store channel ID
        *self.channel_id.write().unwrap() = Some(channel_id);
        *self.connected.write().unwrap() = true;
        
        Ok(())
    }
    
    /// Disconnect from the ATT server
    pub fn disconnect(&self) -> AttResult<()> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Ok(());
        }
        
        // Get channel ID
        let channel_id = match *self.channel_id.read().unwrap() {
            Some(cid) => cid,
            None => return Ok(()),
        };
        
        // Disconnect L2CAP channel
        match self.l2cap_manager.disconnect(channel_id) {
            Ok(_) => {},
            Err(e) => return Err(AttError::from(e)),
        }
        
        // Clear channel ID and state
        *self.channel_id.write().unwrap() = None;
        *self.connected.write().unwrap() = false;
        
        Ok(())
    }
    
    /// Check if connected
    pub fn is_connected(&self) -> bool {
        *self.connected.read().unwrap()
    }
    
    /// Set notification callback
    pub fn set_notification_callback<F>(&self, callback: F)
    where
        F: FnMut(u16, &[u8]) -> AttResult<()> + Send + Sync + 'static,
    {
        let mut notification_callback = self.notification_callback.write().unwrap();
        *notification_callback = Some(Arc::new(Mutex::new(callback)));
    }
    
    /// Set indication callback
    pub fn set_indication_callback<F>(&self, callback: F)
    where
        F: FnMut(u16, &[u8]) -> AttResult<()> + Send + Sync + 'static,
    {
        let mut indication_callback = self.indication_callback.write().unwrap();
        *indication_callback = Some(Arc::new(Mutex::new(callback)));
    }
    
    /// Get the current MTU
    pub fn mtu(&self) -> u16 {
        std::cmp::min(*self.client_mtu.read().unwrap(), *self.server_mtu.read().unwrap())
    }
    
    /// Exchange MTU
    pub fn exchange_mtu(&self, client_mtu: u16) -> AttResult<u16> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Create MTU exchange request
        let req = ExchangeMtuRequest { client_mtu };
        
        // Store our requested MTU
        *self.client_mtu.write().unwrap() = client_mtu;
        
        // Send request
        let response = self.send_request::<ExchangeMtuRequest, ExchangeMtuResponse>(req)?;
        
        // Update server MTU
        *self.server_mtu.write().unwrap() = response.server_mtu;
        
        // Return effective MTU
        Ok(self.mtu())
    }
    
    /// Find information
    pub fn find_information(&self, start_handle: u16, end_handle: u16) -> AttResult<Vec<(u16, Uuid)>> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Create find information request
        let req = FindInformationRequest {
            start_handle,
            end_handle,
        };
        
        // Send request
        let response = self.send_request::<FindInformationRequest, FindInformationResponse>(req)?;
        
        // Convert response to handle-UUID pairs
        let mut results = Vec::new();
        
        for pair in response.information_data {
            match pair {
                HandleUuidPair::Uuid16(handle, uuid16) => {
                    results.push((handle, Uuid::from_u16(uuid16)));
                },
                HandleUuidPair::Uuid128(handle, uuid) => {
                    results.push((handle, uuid));
                },
            }
        }
        
        Ok(results)
    }
    
    /// Find by type value
    pub fn find_by_type_value(
        &self,
        start_handle: u16,
        end_handle: u16,
        type_uuid: u16,
        value: &[u8]
    ) -> AttResult<Vec<(u16, u16)>> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Create find by type value request
        let req = FindByTypeValueRequest {
            start_handle,
            end_handle,
            attribute_type: type_uuid,
            attribute_value: value.to_vec(),
        };
        
        // Send request
        let response = self.send_request::<FindByTypeValueRequest, FindByTypeValueResponse>(req)?;
        
        // Convert response to handle ranges
        let results = response.handles.iter()
            .map(|range| (range.found_handle, range.group_end_handle))
            .collect();
        
        Ok(results)
    }
    
    /// Read by type
    pub fn read_by_type(
        &self,
        start_handle: u16,
        end_handle: u16,
        attr_type: &Uuid
    ) -> AttResult<Vec<(u16, Vec<u8>)>> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Create read by type request
        let req = ReadByTypeRequest {
            start_handle,
            end_handle,
            attribute_type: attr_type.clone(),
        };
        
        // Send request
        let response = self.send_request::<ReadByTypeRequest, ReadByTypeResponse>(req)?;
        
        // Convert response to handle-value pairs
        let results = response.data.iter()
            .map(|item| (item.handle, item.value.clone()))
            .collect();
        
        Ok(results)
    }
    
    /// Read attribute
    pub fn read(&self, handle: u16) -> AttResult<Vec<u8>> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Create read request
        let req = ReadRequest { handle };
        
        // Send request
        let response = self.send_request::<ReadRequest, ReadResponse>(req)?;
        
        Ok(response.value)
    }
    
    /// Read blob
    pub fn read_blob(&self, handle: u16, offset: u16) -> AttResult<Vec<u8>> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Create read blob request
        let req = ReadBlobRequest {
            handle,
            offset,
        };
        
        // Send request
        let response = self.send_request::<ReadBlobRequest, ReadBlobResponse>(req)?;
        
        Ok(response.value)
    }
    
    /// Read multiple attributes
    pub fn read_multiple(&self, handles: &[u16]) -> AttResult<Vec<u8>> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Create read multiple request
        let req = ReadMultipleRequest {
            handles: handles.to_vec(),
        };
        
        // Send request
        let response = self.send_request::<ReadMultipleRequest, ReadMultipleResponse>(req)?;
        
        Ok(response.values)
    }
    
    /// Read by group type
    pub fn read_by_group_type(
        &self,
        start_handle: u16,
        end_handle: u16,
        group_type: &Uuid
    ) -> AttResult<Vec<(u16, u16, Vec<u8>)>> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Create read by group type request
        let req = ReadByGroupTypeRequest {
            start_handle,
            end_handle,
            group_type: group_type.clone(),
        };
        
        // Send request
        let response = self.send_request::<ReadByGroupTypeRequest, ReadByGroupTypeResponse>(req)?;
        
        // Convert response to handle-end_handle-value tuples
        let results = response.data.iter()
            .map(|item| (item.handle, item.end_group_handle, item.value.clone()))
            .collect();
        
        Ok(results)
    }
    
    /// Write request
    pub fn write(&self, handle: u16, value: &[u8]) -> AttResult<()> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Check if value is too long
        let mtu = self.mtu();
        if value.len() > (mtu as usize - 3) {
            return Err(AttError::InvalidAttributeValueLength);
        }
        
        // Create write request
        let req = WriteRequest {
            handle,
            value: value.to_vec(),
        };
        
        // Send request
        let _ = self.send_request::<WriteRequest, WriteResponse>(req)?;
        
        Ok(())
    }
    
    /// Write command (no response)
    pub fn write_command(&self, handle: u16, value: &[u8]) -> AttResult<()> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Check if value is too long
        let mtu = self.mtu();
        if value.len() > (mtu as usize - 3) {
            return Err(AttError::InvalidAttributeValueLength);
        }
        
        // Create write command
        let cmd = WriteCommand {
            handle,
            value: value.to_vec(),
        };
        
        // Send command
        self.send_command::<WriteCommand>(cmd)?;
        
        Ok(())
    }
    
    /// Prepare write request
    pub fn prepare_write(&self, handle: u16, offset: u16, value: &[u8]) -> AttResult<()> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Check if value is too long
        let mtu = self.mtu();
        if value.len() > (mtu as usize - 5) {
            return Err(AttError::InvalidAttributeValueLength);
        }
        
        // Create prepare write request
        let req = PrepareWriteRequest {
            handle,
            offset,
            value: value.to_vec(),
        };
        
        // Send request
        let response = self.send_request::<PrepareWriteRequest, PrepareWriteResponse>(req)?;
        
        // Verify the response matches the request
        if response.handle != handle || response.offset != offset || response.value != value {
            return Err(AttError::UnlikelyError);
        }
        
        Ok(())
    }
    
    /// Execute write request
    pub fn execute_write(&self, flags: u8) -> AttResult<()> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Create execute write request
        let req = ExecuteWriteRequest { flags };
        
        // Send request
        let _ = self.send_request::<ExecuteWriteRequest, ExecuteWriteResponse>(req)?;
        
        Ok(())
    }
    
    /// Handle ATT PDU received from server
    pub fn handle_att_pdu(&self, data: &[u8]) -> AttResult<()> {
        if data.is_empty() {
            return Err(AttError::InvalidPdu);
        }
        
        let opcode = data[0];
        
        match opcode {
            ATT_ERROR_RSP |
            ATT_EXCHANGE_MTU_RSP |
            ATT_FIND_INFO_RSP |
            ATT_FIND_BY_TYPE_VALUE_RSP |
            ATT_READ_BY_TYPE_RSP |
            ATT_READ_RSP |
            ATT_READ_BLOB_RSP |
            ATT_READ_MULTIPLE_RSP |
            ATT_READ_BY_GROUP_TYPE_RSP |
            ATT_WRITE_RSP |
            ATT_PREPARE_WRITE_RSP |
            ATT_EXECUTE_WRITE_RSP => {
                // Response to a request, find the transaction
                self.handle_response(opcode, data)
            },
            ATT_HANDLE_VALUE_NTF => {
                // Notification
                self.handle_notification(data)
            },
            ATT_HANDLE_VALUE_IND => {
                // Indication
                self.handle_indication(data)
            },
            _ => {
                // Unknown/unexpected PDU
                Err(AttError::InvalidPdu)
            }
        }
    }
    
    /// Handle response from server
    fn handle_response(&self, opcode: u8, data: &[u8]) -> AttResult<()> {
        let mut transactions = self.transactions.write().unwrap();
        
        // Find the transaction this is a response to
        let req_opcode = if opcode == ATT_ERROR_RSP {
            // For error responses, the request opcode is in the PDU
            if data.len() < 2 {
                return Err(AttError::InvalidPdu);
            }
            data[1]
        } else {
            // For other responses, it's the corresponding request opcode
            match opcode {
                ATT_EXCHANGE_MTU_RSP => ATT_EXCHANGE_MTU_REQ,
                ATT_FIND_INFO_RSP => ATT_FIND_INFO_REQ,
                ATT_FIND_BY_TYPE_VALUE_RSP => ATT_FIND_BY_TYPE_VALUE_REQ,
                ATT_READ_BY_TYPE_RSP => ATT_READ_BY_TYPE_REQ,
                ATT_READ_RSP => ATT_READ_REQ,
                ATT_READ_BLOB_RSP => ATT_READ_BLOB_REQ,
                ATT_READ_MULTIPLE_RSP => ATT_READ_MULTIPLE_REQ,
                ATT_READ_BY_GROUP_TYPE_RSP => ATT_READ_BY_GROUP_TYPE_REQ,
                ATT_WRITE_RSP => ATT_WRITE_REQ,
                ATT_PREPARE_WRITE_RSP => ATT_PREPARE_WRITE_REQ,
                ATT_EXECUTE_WRITE_RSP => ATT_EXECUTE_WRITE_REQ,
                _ => return Err(AttError::InvalidPdu),
            }
        };
        
        // Find and update the transaction
        if let Some(transaction) = transactions.get_mut(&req_opcode) {
            if opcode == ATT_ERROR_RSP {
                // Parse the error
                if data.len() < 4 {
                    transaction.error = Some(AttError::InvalidPdu);
                } else {
                    let error_code: AttErrorCode = data[3].into();
                    let handle = ((data[2] as u16) << 8) | (data[1] as u16);
                    transaction.error = Some(AttError::Protocol(error_code, handle));
                }
            } else {
                // Store the response data
                transaction.response = Some(data.to_vec());
            }
            
            Ok(())
        } else {
            // Unexpected response
            Err(AttError::InvalidPdu)
        }
    }
    
    /// Handle notification from server
    fn handle_notification(&self, data: &[u8]) -> AttResult<()> {
        // Parse notification
        if data.len() < 3 {
            return Err(AttError::InvalidPdu);
        }
        
        let handle = ((data[2] as u16) << 8) | (data[1] as u16);
        let value = &data[3..];
        
        // Call notification callback if registered
        let notification_callback = self.notification_callback.read().unwrap();
        if let Some(ref callback) = *notification_callback {
            let mut callback = callback.lock().unwrap();
            (*callback)(handle, value)?;
        }
        
        Ok(())
    }
    
    /// Handle indication from server
    fn handle_indication(&self, data: &[u8]) -> AttResult<()> {
        // Parse indication
        if data.len() < 3 {
            return Err(AttError::InvalidPdu);
        }
        
        let handle = ((data[2] as u16) << 8) | (data[1] as u16);
        let value = &data[3..];
        
        // Call indication callback if registered
        let indication_callback = self.indication_callback.read().unwrap();
        if let Some(ref callback) = *indication_callback {
            let mut callback = callback.lock().unwrap();
            (*callback)(handle, value)?;
        }
        
        // Send confirmation
        let conf = HandleValueConfirmation;
        self.send_command::<HandleValueConfirmation>(conf)?;
        
        Ok(())
    }
    
    /// Send a request and wait for the response
    fn send_request<Req: AttPacket, Resp: AttPacket>(&self, request: Req) -> AttResult<Resp> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Get channel ID
        let channel_id = match *self.channel_id.read().unwrap() {
            Some(cid) => cid,
            None => return Err(AttError::InvalidState),
        };
        
        // Serialize the request
        let request_data = request.serialize();
        
        // Create a transaction
        let req_opcode = Req::opcode();
        let transaction = AttTransaction {
            opcode: req_opcode,
            response: None,
            start_time: Instant::now(),
            error: None,
        };
        
        // Store the transaction
        {
            let mut transactions = self.transactions.write().unwrap();
            transactions.insert(req_opcode, transaction);
        }
        
        // Send the request
        match self.l2cap_manager.send_data(channel_id, &request_data) {
            Ok(_) => {},
            Err(e) => return Err(AttError::from(e)),
        }
        
        // Wait for the response or timeout
        let start_time = Instant::now();
        loop {
            // Check if response has arrived
            let mut transaction_opt = None;
            {
                let mut transactions = self.transactions.write().unwrap();
                if let Some(transaction) = transactions.get(&req_opcode) {
                    if transaction.response.is_some() || transaction.error.is_some() {
                        transaction_opt = Some(transactions.remove(&req_opcode).unwrap());
                    }
                }
            }
            
            if let Some(transaction) = transaction_opt {
                // Process the result
                if let Some(error) = transaction.error {
                    return Err(error);
                }
                
                if let Some(response_data) = transaction.response {
                    // Parse the response
                    return Resp::parse(&response_data);
                }
            }
            
            // Check for timeout
            if start_time.elapsed().as_millis() > ATT_TRANSACTION_TIMEOUT as u128 {
                // Remove the transaction
                {
                    let mut transactions = self.transactions.write().unwrap();
                    transactions.remove(&req_opcode);
                }
                
                return Err(AttError::Unknown("Transaction timeout".into()));
            }
            
            // Small sleep to avoid busy loop
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    
    /// Send a command (no response)
    fn send_command<Cmd: AttPacket>(&self, command: Cmd) -> AttResult<()> {
        // Check if connected
        if !*self.connected.read().unwrap() {
            return Err(AttError::InvalidState);
        }
        
        // Get channel ID
        let channel_id = match *self.channel_id.read().unwrap() {
            Some(cid) => cid,
            None => return Err(AttError::InvalidState),
        };
        
        // Serialize the command
        let command_data = command.serialize();
        
        // Send the command
        match self.l2cap_manager.send_data(channel_id, &command_data) {
            Ok(_) => Ok(()),
            Err(e) => Err(AttError::from(e)),
        }
    }
    
    /// Process timeouts for pending transactions
    pub fn process_timeouts(&self) -> AttResult<()> {
        let mut expired_transactions = Vec::new();
        
        // Find expired transactions
        {
            let transactions = self.transactions.read().unwrap();
            for (&opcode, transaction) in transactions.iter() {
                if transaction.start_time.elapsed().as_millis() > ATT_TRANSACTION_TIMEOUT as u128 {
                    expired_transactions.push(opcode);
                }
            }
        }
        
        // Remove expired transactions
        {
            let mut transactions = self.transactions.write().unwrap();
            for opcode in expired_transactions {
                transactions.remove(&opcode);
            }
        }
        
        Ok(())
    }
}