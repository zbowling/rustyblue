//! L2CAP Core Manager implementation
//!
//! This module provides the core L2CAP manager that handles:
//! - Channel management
//! - Data routing
//! - Signaling commands
//! - Connection setup and teardown

use crate::error::{Error, HciError};
use crate::hci::socket::HciSocket;
use crate::l2cap::types::{L2capError, L2capResult, ConnectionType, ChannelId, ConfigureResult, L2capChannelState, ConfigOptions, ConnectionParameterUpdate, SecurityLevel, LeCreditBasedConfig, ConnectionPolicy};
use crate::l2cap::channel::{L2capChannel, DataCallback};
use crate::l2cap::packet::{L2capPacket};
use crate::l2cap::psm::PSM;
use crate::l2cap::signaling::SignalingMessage;
use crate::l2cap::ChannelEventCallback;
use crate::l2cap::constants::*;
use log::{debug, error, info, trace, warn};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Callback for channel events like connect, disconnect, etc.
pub type ChannelEventCallback = Arc<Mutex<dyn FnMut(ChannelEvent) -> L2capResult<()> + Send + 'static>>;

/// Channel events for callbacks
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    /// Channel connected
    Connected {
        /// Channel ID
        cid: ChannelId,
        /// Protocol/Service Multiplexer
        psm: PSM,
    },
    /// Channel disconnected
    Disconnected {
        /// Channel ID
        cid: ChannelId,
        /// Protocol/Service Multiplexer
        psm: Option<PSM>,
        /// Reason for disconnection
        reason: String,
    },
    /// Channel configuration changed
    ConfigChanged {
        /// Channel ID
        cid: ChannelId,
        /// New configuration
        config: ConfigOptions,
    },
    /// Connection request received
    ConnectionRequest {
        /// Signal identifier for responding
        identifier: u8,
        /// Protocol/Service Multiplexer
        psm: PSM,
        /// Source Channel ID (remote device)
        source_cid: ChannelId,
    },
    /// Connection parameter update request (LE only)
    ConnectionParameterUpdateRequest {
        /// Signal identifier for responding
        identifier: u8,
        /// Connection parameters
        params: ConnectionParameterUpdate,
    },
}

/// Represents a registration for a specific PSM.
#[derive(Clone)]
struct PsmRegistration {
    /// PSM value
    psm: PSM,
    /// Data callback for this PSM
    data_callback: Option<DataCallback>,
    /// Event callback for this PSM
    event_callback: Option<ChannelEventCallback>,
    /// Security requirements
    security_level: SecurityLevel,
    /// Whether authorization is required
    authorization_required: bool,
    /// Whether to auto-accept connections
    auto_accept: bool,
}

/// L2CAP Manager responsible for handling L2CAP operations
pub struct L2capManager {
    /// Channels mapped by local CID
    channels: RwLock<HashMap<ChannelId, L2capChannel>>,
    
    /// Registered PSMs
    psm_registrations: RwLock<HashMap<u16, PsmRegistration>>,
    
    /// Map of remote HCI handles to local CIDs
    handle_to_cid: RwLock<HashMap<u16, Vec<ChannelId>>>,
    
    /// Next available dynamic CID
    next_cid: Mutex<ChannelId>,
    
    /// Pending signaling transactions
    pending_transactions: RwLock<HashMap<u8, SignalingTransaction>>,
    
    /// Next available signaling identifier
    next_signal_id: Mutex<u8>,
    
    /// Connection type (Classic or LE)
    connection_type: ConnectionType,
    
    /// Event callback for all channels
    global_event_callback: Mutex<Option<ChannelEventCallback>>,
}

/// Signaling transaction state
#[derive(Debug)]
struct SignalingTransaction {
    /// Transaction type
    transaction_type: SignalingTransactionType,
    /// Timestamp when the transaction was started
    timestamp: Instant,
    /// Number of retries attempted
    retries: u8,
}

/// Type of signaling transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalingTransactionType {
    /// Connection request
    Connect(PSM, ChannelId),  // PSM, local CID
    /// Disconnection request
    Disconnect(ChannelId, ChannelId),  // local CID, remote CID
    /// Configuration request
    Configure(ChannelId),     // remote CID
    /// Information request
    Information(u16),   // info type
    /// Echo request
    Echo,
    /// Connection parameter update request (LE only)
    ConnectionParameterUpdate,
}

impl L2capManager {
    /// Create a new L2CAP Manager
    pub fn new(connection_type: ConnectionType) -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
            psm_registrations: RwLock::new(HashMap::new()),
            handle_to_cid: RwLock::new(HashMap::new()),
            next_cid: Mutex::new(L2CAP_DYNAMIC_CID_MIN),
            pending_transactions: RwLock::new(HashMap::new()),
            next_signal_id: Mutex::new(1),  // Start from 1
            connection_type,
            global_event_callback: Mutex::new(None),
        }
    }
    
    /// Register a PSM for handling incoming connections
    pub fn register_psm(
        &self, 
        psm: PSM, 
        data_callback: Option<DataCallback>,
        event_callback: Option<ChannelEventCallback>,
        policy: ConnectionPolicy
    ) -> L2capResult<()> {
        if !psm.is_valid() {
            return Err(L2capError::InvalidParameter("Invalid PSM".into()));
        }
        
        let mut registrations = self.psm_registrations.write().unwrap();
        
        // Check if PSM is already registered
        if registrations.contains_key(&psm.value()) {
            return Err(L2capError::InvalidParameter(format!("PSM {:?} already registered", psm)));
        }
        
        // Register the PSM
        registrations.insert(psm.value(), PsmRegistration {
            psm,
            data_callback,
            event_callback,
            security_level: policy.min_security_level,
            authorization_required: policy.authorization_required,
            auto_accept: policy.auto_accept,
        });
        
        Ok(())
    }
    
    /// Unregister a PSM
    pub fn unregister_psm(&self, psm: PSM) -> L2capResult<()> {
        let mut registrations = self.psm_registrations.write().unwrap();
        
        if registrations.remove(&psm.value()).is_none() {
            return Err(L2capError::PsmNotRegistered);
        }
        
        Ok(())
    }
    
    /// Set the global event callback for all channels
    pub fn set_global_event_callback<F>(&self, callback: F)
    where
        F: FnMut(ChannelEvent) -> L2capResult<()> + Send + 'static
    {
        let mut global_callback = self.global_event_callback.lock().unwrap();
        *global_callback = Some(Arc::new(Mutex::new(callback)));
    }
    
    /// Allocate a new dynamic CID
    fn allocate_cid(&self) -> L2capResult<ChannelId> {
        let mut next_cid = self.next_cid.lock().unwrap();
        let starting_cid = *next_cid;
        
        let channels = self.channels.read().unwrap();
        
        // Find the next available CID
        loop {
            if !channels.contains_key(&*next_cid) {
                let allocated_cid = *next_cid;
                
                // Increment for next time
                *next_cid += 1;
                if *next_cid >= L2CAP_DYNAMIC_CID_MAX || *next_cid < L2CAP_DYNAMIC_CID_MIN {
                    *next_cid = L2CAP_DYNAMIC_CID_MIN;
                }
                
                return Ok(allocated_cid);
            }
            
            *next_cid += 1;
            if *next_cid >= L2CAP_DYNAMIC_CID_MAX || *next_cid < L2CAP_DYNAMIC_CID_MIN {
                *next_cid = L2CAP_DYNAMIC_CID_MIN;
            }
            
            // Check if we've gone full circle
            if *next_cid == starting_cid {
                return Err(L2capError::ResourceLimitReached);
            }
        }
    }
    
    /// Allocate the next signal identifier
    fn allocate_signal_id(&self) -> u8 {
        let mut next_id = self.next_signal_id.lock().unwrap();
        let id = *next_id;
        
        *next_id += 1;
        if *next_id == 0 {
            *next_id = 1;  // Skip 0
        }
        
        id
    }
    
    /// Connect to a remote device for a specific PSM
    pub fn connect(&self, psm: PSM, hci_handle: u16) -> L2capResult<ChannelId> {
        if !psm.is_valid() {
            return Err(L2capError::InvalidParameter("Invalid PSM".into()));
        }
        
        // Allocate a local CID
        let local_cid = self.allocate_cid()?;
        
        // Create a new channel
        let channel = if self.connection_type == ConnectionType::LE {
            L2capChannel::new_le_credit_based(
                local_cid,
                psm,
                LeCreditBasedConfig::default(),
            )
        } else {
            L2capChannel::new_dynamic(local_cid, psm, self.connection_type)
        };
        
        // Add the channel to our map
        {
            let mut channels = self.channels.write().unwrap();
            channels.insert(local_cid, channel);
        }
        
        // Associate the channel with the HCI handle
        {
            let mut handle_map = self.handle_to_cid.write().unwrap();
            handle_map.entry(hci_handle).or_insert_with(Vec::new).push(local_cid);
        }
        
        // Create a connection request
        let signal_id = self.allocate_signal_id();
        
        // Store the transaction for tracking
        {
            let mut transactions = self.pending_transactions.write().unwrap();
            transactions.insert(signal_id, SignalingTransaction {
                transaction_type: SignalingTransactionType::Connect(psm, local_cid),
                timestamp: Instant::now(),
                retries: 0,
            });
        }
        
        // Create the signaling message
        let message = if self.connection_type == ConnectionType::LE {
            SignalingMessage::LeCreditBasedConnectionRequest {
                identifier: signal_id,
                le_psm: psm.value(),
                source_cid: local_cid,
                mtu: L2CAP_LE_DEFAULT_MTU,
                mps: L2CAP_LE_DEFAULT_MTU,
                initial_credits: 10, // Default initial credits
            }
        } else {
            SignalingMessage::ConnectionRequest {
                identifier: signal_id,
                psm,
                source_cid: local_cid,
            }
        };
        
        // Update channel state
        {
            let mut channels = self.channels.write().unwrap();
            if let Some(channel) = channels.get_mut(&local_cid) {
                channel.set_state(L2capChannelState::WaitConnectRsp);
            }
        }
        
        // Send the connection request (would be sent through HCI in a real implementation)
        // This would typically involve converting to an L2CAP packet and sending via HCI ACL
        
        Ok(local_cid)
    }
    
    /// Disconnect a channel
    pub fn disconnect(&self, local_cid: ChannelId) -> L2capResult<()> {
        let (remote_cid, handle) = {
            let channels = self.channels.read().unwrap();
            
            let channel = channels.get(&local_cid)
                .ok_or(L2capError::ChannelNotFound)?;
                
            if channel.state() == L2capChannelState::Closed {
                return Err(L2capError::InvalidState);
            }
            
            (channel.remote_cid(), 0) // We would get the handle from somewhere
        };
        
        if remote_cid == 0 {
            return Err(L2capError::NotConnected);
        }
        
        // Create a disconnection request
        let signal_id = self.allocate_signal_id();
        
        // Store the transaction
        {
            let mut transactions = self.pending_transactions.write().unwrap();
            transactions.insert(signal_id, SignalingTransaction {
                transaction_type: SignalingTransactionType::Disconnect(local_cid, remote_cid),
                timestamp: Instant::now(),
                retries: 0,
            });
        }
        
        // Create the signaling message
        let message = SignalingMessage::DisconnectionRequest {
            identifier: signal_id,
            destination_cid: remote_cid,
            source_cid: local_cid,
        };
        
        // Update channel state
        {
            let mut channels = self.channels.write().unwrap();
            if let Some(channel) = channels.get_mut(&local_cid) {
                channel.set_state(L2capChannelState::WaitDisconnect);
            }
        }
        
        // Send the disconnection request (would be sent via HCI)
        
        Ok(())
    }
    
    /// Configure a channel with specific options
    pub fn configure(&self, local_cid: ChannelId, options: ConfigOptions) -> L2capResult<()> {
        let remote_cid = {
            let channels = self.channels.read().unwrap();
            
            let channel = channels.get(&local_cid)
                .ok_or(L2capError::ChannelNotFound)?;
                
            if channel.state() != L2capChannelState::WaitConfig &&
               channel.state() != L2capChannelState::WaitConfigReq &&
               channel.state() != L2capChannelState::Open {
                return Err(L2capError::InvalidState);
            }
            
            channel.remote_cid()
        };
        
        if remote_cid == 0 {
            return Err(L2capError::NotConnected);
        }
        
        // Create a configuration request
        let signal_id = self.allocate_signal_id();
        
        // Store the transaction
        {
            let mut transactions = self.pending_transactions.write().unwrap();
            transactions.insert(signal_id, SignalingTransaction {
                transaction_type: SignalingTransactionType::Configure(remote_cid),
                timestamp: Instant::now(),
                retries: 0,
            });
        }
        
        // Create the signaling message
        let message = SignalingMessage::ConfigureRequest {
            identifier: signal_id,
            destination_cid: remote_cid,
            flags: 0,
            options,
        };
        
        // Send the configuration request (would be sent via HCI)
        
        Ok(())
    }
    
    /// Send data on a channel
    pub fn send_data(&self, local_cid: ChannelId, data: &[u8]) -> L2capResult<()> {
        let packet = {
            let channels = self.channels.read().unwrap();
            
            let channel = channels.get(&local_cid)
                .ok_or(L2capError::ChannelNotFound)?;
                
            if channel.state() != L2capChannelState::Open {
                return Err(L2capError::InvalidState);
            }
            
            channel.create_data_packet(data)?
        };
        
        // Send the packet (would be sent via HCI)
        // The actual sending would depend on the underlying transport
        
        Ok(())
    }
    
    /// Handle a received L2CAP packet
    pub fn handle_packet(&self, packet: L2capPacket, hci_handle: u16) -> L2capResult<()> {
        match packet.header.channel_id {
            L2CAP_SIGNALING_CID => {
                self.handle_signaling_packet(packet, hci_handle, false)
            },
            L2CAP_LE_SIGNALING_CID => {
                self.handle_signaling_packet(packet, hci_handle, true)
            },
            _ => {
                // Data packet for a specific channel
                self.handle_data_packet(packet, hci_handle)
            }
        }
    }
    
    /// Handle a received signaling packet
    fn handle_signaling_packet(&self, packet: L2capPacket, hci_handle: u16, is_le: bool) -> L2capResult<()> {
        // Parse the signaling message from the packet payload
        let message = SignalingMessage::parse(&packet.payload, is_le)?;
        
        match message {
            SignalingMessage::ConnectionRequest { identifier, psm, source_cid } => {
                self.handle_connection_request(identifier, psm, source_cid, hci_handle)
            },
            SignalingMessage::ConnectionResponse { identifier, destination_cid, source_cid, result, status } => {
                self.handle_connection_response(identifier, destination_cid, source_cid, result, status)
            },
            SignalingMessage::ConfigureRequest { identifier, destination_cid, flags, options } => {
                self.handle_configure_request(destination_cid, identifier, flags, options, hci_handle)
            },
            SignalingMessage::ConfigureResponse { identifier, source_cid, flags, result, options } => {
                self.handle_configure_response(identifier, source_cid, flags, result, options)
            },
            SignalingMessage::DisconnectionRequest { identifier, destination_cid, source_cid } => {
                self.handle_disconnection_request(identifier, destination_cid, source_cid, hci_handle)
            },
            SignalingMessage::DisconnectionResponse { identifier, destination_cid, source_cid } => {
                self.handle_disconnection_response(identifier, destination_cid, source_cid)
            },
            SignalingMessage::ConnectionParameterUpdateRequest { identifier, params } => {
                self.handle_connection_parameter_update_request(identifier, params, hci_handle)
            },
            SignalingMessage::ConnectionParameterUpdateResponse { identifier, result } => {
                self.handle_connection_parameter_update_response(identifier, result)
            },
            SignalingMessage::LeCreditBasedConnectionRequest { identifier, le_psm, source_cid, mtu, mps, initial_credits } => {
                self.handle_le_credit_based_connection_request(
                    identifier, le_psm, source_cid, mtu, mps, initial_credits, hci_handle
                )
            },
            SignalingMessage::LeCreditBasedConnectionResponse { identifier, destination_cid, mtu, mps, initial_credits, result } => {
                self.handle_le_credit_based_connection_response(
                    identifier, destination_cid, mtu, mps, initial_credits, result
                )
            },
            SignalingMessage::LeFlowControlCredit { identifier, cid, credits } => {
                self.handle_le_flow_control_credit(identifier, cid, credits)
            },
            // Handle other signaling messages
            _ => {
                // For now, reject unhandled messages
                self.send_command_reject(message.get_identifier(), L2CAP_REJECT_NOT_UNDERSTOOD, &[], hci_handle)
            }
        }
    }
    
    /// Handle a received data packet
    fn handle_data_packet(&self, packet: L2capPacket, hci_handle: u16) -> L2capResult<()> {
        // Find the channel for this packet
        let local_cid = {
            let channels = self.channels.read().unwrap();
            
            // Look for a channel with matching remote CID
            let mut found_cid = None;
            for (local_cid, channel) in channels.iter() {
                if channel.remote_cid() == packet.header.channel_id {
                    found_cid = Some(*local_cid);
                    break;
                }
            }
            
            found_cid.ok_or(L2capError::ChannelNotFound)?
        };
        
        // Process the data packet
        {
            let mut channels = self.channels.write().unwrap();
            if let Some(channel) = channels.get_mut(&local_cid) {
                if channel.state() != L2capChannelState::Open {
                    return Err(L2capError::InvalidState);
                }
                
                channel.handle_data(&packet.payload)?;
            } else {
                return Err(L2capError::ChannelNotFound);
            }
        }
        
        Ok(())
    }
    
    /// Handle a connection request
    fn handle_connection_request(
        &self, 
        identifier: u8, 
        psm: PSM, 
        source_cid: ChannelId, 
        hci_handle: u16
    ) -> L2capResult<()> {
        // Check if PSM is registered
        let registration = {
            let registrations = self.psm_registrations.read().unwrap();
            
            registrations.get(&psm.value())
                .cloned()
                .ok_or(L2capError::PsmNotRegistered)?
        };
        
        // Allocate a local CID
        let local_cid = self.allocate_cid()?;
        
        // Create a new channel
        let mut channel = L2capChannel::new_dynamic(local_cid, psm, self.connection_type);
        channel.set_remote_cid(source_cid);
        
        // Set data callback if registered
        if let Some(ref callback) = registration.data_callback {
            channel.set_data_callback(move |data| {
                let mut callback = callback.lock().unwrap();
                (*callback)(data)
            });
        }
        
        // Add the channel to our map
        {
            let mut channels = self.channels.write().unwrap();
            channels.insert(local_cid, channel);
        }
        
        // Associate the channel with the HCI handle
        {
            let mut handle_map = self.handle_to_cid.write().unwrap();
            handle_map.entry(hci_handle).or_insert_with(Vec::new).push(local_cid);
        }
        
        // Notify event handlers
        let event = ChannelEvent::ConnectionRequest {
            identifier,
            psm,
            source_cid,
        };
        
        // If the connection is auto-accepted, send response immediately
        if registration.auto_accept {
            // Send connection response
            let response = SignalingMessage::ConnectionResponse {
                identifier,
                destination_cid: local_cid,
                source_cid,
                result: L2CAP_RESULT_SUCCESS,
                status: 0,
            };
            
            // Update channel state
            {
                let mut channels = self.channels.write().unwrap();
                if let Some(channel) = channels.get_mut(&local_cid) {
                    channel.set_state(L2capChannelState::WaitConfig);
                }
            }
            
            // Send the response (would be sent via HCI)
            
            // Notify event handlers of connection
            self.notify_event_handlers(ChannelEvent::Connected {
                cid: local_cid,
                psm,
            });
        } else {
            // Let the application decide
            self.notify_event_handlers(event);
        }
        
        Ok(())
    }
    
    /// Accept a pending connection request
    pub fn accept_connection(&self, identifier: u8, local_cid: ChannelId, hci_handle: u16) -> L2capResult<()> {
        let (source_cid, psm) = {
            let mut channels = self.channels.write().unwrap();
            
            let channel = channels.get_mut(&local_cid)
                .ok_or(L2capError::ChannelNotFound)?;
                
            if channel.state() != L2capChannelState::Closed {
                return Err(L2capError::InvalidState);
            }
            
            channel.set_state(L2capChannelState::WaitConfig);
            
            (channel.remote_cid(), channel.psm())
        };
        
        if source_cid == 0 {
            return Err(L2capError::NotConnected);
        }
        
        // Send connection response
        let response = SignalingMessage::ConnectionResponse {
            identifier,
            destination_cid: local_cid,
            source_cid,
            result: L2CAP_RESULT_SUCCESS,
            status: 0,
        };
        
        // Send the response (would be sent via HCI)
        
        // Notify event handlers
        if let Some(psm) = psm {
            self.notify_event_handlers(ChannelEvent::Connected {
                cid: local_cid,
                psm,
            });
        }
        
        Ok(())
    }
    
    /// Reject a pending connection request
    pub fn reject_connection(
        &self, 
        identifier: u8, 
        local_cid: ChannelId, 
        source_cid: ChannelId,
        reason: u16,
        hci_handle: u16
    ) -> L2capResult<()> {
        // Send connection response with failure
        let response = SignalingMessage::ConnectionResponse {
            identifier,
            destination_cid: 0, // Invalid CID, we're rejecting
            source_cid,
            result: reason,
            status: 0,
        };
        
        // Send the response (would be sent via HCI)
        
        // Remove the channel
        {
            let mut channels = self.channels.write().unwrap();
            channels.remove(&local_cid);
        }
        
        Ok(())
    }
    
    /// Handle a connection response
    fn handle_connection_response(
        &self,
        identifier: u8,
        destination_cid: ChannelId,
        source_cid: ChannelId,
        result: u16,
        status: u16
    ) -> L2capResult<()> {
        // Find the pending transaction
        let transaction = {
            let mut transactions = self.pending_transactions.write().unwrap();
            transactions.remove(&identifier)
        };
        
        if let Some(transaction) = transaction {
            match transaction.transaction_type {
                SignalingTransactionType::Connect(psm, local_cid) => {
                    if local_cid != source_cid {
                        return Err(L2capError::InvalidParameter("Mismatched source CID".into()));
                    }
                    
                    if result == L2CAP_RESULT_SUCCESS {
                        // Connection successful
                        {
                            let mut channels = self.channels.write().unwrap();
                            if let Some(channel) = channels.get_mut(&local_cid) {
                                channel.set_remote_cid(destination_cid);
                                channel.set_state(L2capChannelState::WaitConfig);
                            } else {
                                return Err(L2capError::ChannelNotFound);
                            }
                        }
                        
                        // Notify event handlers
                        self.notify_event_handlers(ChannelEvent::Connected {
                            cid: local_cid,
                            psm,
                        });
                        
                        // Send configuration request
                        // self.configure(local_cid, ConfigOptions::default())?;
                    } else if result == L2CAP_RESULT_PENDING && status != 0 {
                        // Connection pending, waiting for user acceptance
                        // Do nothing for now, wait for the final response
                    } else {
                        // Connection failed
                        {
                            let mut channels = self.channels.write().unwrap();
                            channels.remove(&local_cid);
                        }
                        
                        // Notify event handlers of disconnection
                        self.notify_event_handlers(ChannelEvent::Disconnected {
                            cid: local_cid,
                            psm: Some(psm),
                            reason: format!("Connection failed: result={}, status={}", result, status),
                        });
                    }
                },
                _ => {
                    return Err(L2capError::ProtocolError("Unexpected connection response".into()));
                }
            }
        } else {
            // No pending transaction for this response
            return Err(L2capError::ProtocolError("Unexpected connection response".into()));
        }
        
        Ok(())
    }
    
    /// Handle a configure request
    fn handle_configure_request(
        &self,
        remote_cid: ChannelId,
        identifier: u8,
        flags: u16,
        options: ConfigOptions,
        hci_handle: u16
    ) -> L2capResult<()> {
        debug!("Handling Configure Request for CID {}", remote_cid);
        let mut channels = self.channels.write().unwrap();
        if let Some(channel) = channels.get_mut(&remote_cid) {
            let (response_result, response_options) = channel.configure(&options)?;
            let response = SignalingMessage::ConfigureResponse {
                identifier,
                source_cid: channel.local_cid(),
                flags: 0,
                result: response_result.to_result_code(),
                options: response_options,
            };
            self.send_signaling_message(hci_handle, channel.local_cid(), response)?; 
            
            if response_result == ConfigureResult::Success && flags == 0 { 
                if channel.state() == L2capChannelState::WaitConfig {
                    channel.set_state(L2capChannelState::WaitConfigReq);
                } else if channel.state() == L2capChannelState::WaitConfigReq {
                    channel.set_state(L2capChannelState::Open);
                    info!("L2CAP channel {} is OPEN", remote_cid);
                }
            }
        } else {
            warn!("Received Configure Request for unknown CID {}", remote_cid);
        }
        Ok(())
    }
    
    /// Handle a configure response
    fn handle_configure_response(
        &self,
        identifier: u8,
        source_cid: ChannelId,
        flags: u16,
        result: u16,
        options: ConfigOptions
    ) -> L2capResult<()> {
        // Find the pending transaction
        let transaction = {
            let mut transactions = self.pending_transactions.write().unwrap();
            transactions.remove(&identifier)
        };
        
        if let Some(transaction) = transaction {
            match transaction.transaction_type {
                SignalingTransactionType::Configure(remote_cid) => {
                    let local_cid = source_cid;
                    if result == L2CAP_RESULT_SUCCESS {
                        {
                            let mut channels = self.channels.write().unwrap();
                            if let Some(channel) = channels.get_mut(&local_cid) {
                                let options = options.clone();
                                let peer_mtu = options.mtu.unwrap_or(L2CAP_DEFAULT_MTU);
                                let options_valid = peer_mtu >= L2CAP_LE_DEFAULT_MTU;
                                if !options_valid {
                                    // Reject configuration
                                    return Ok(());
                                }
                                
                                // Update channel state
                                if channel.state() == L2capChannelState::WaitConfig {
                                    channel.set_state(L2capChannelState::WaitConfigReq);
                                } else if channel.state() == L2capChannelState::WaitFinalConfig {
                                    channel.set_state(L2capChannelState::Open);
                                }
                            } else {
                                return Err(L2capError::ChannelNotFound);
                            }
                        }
                        
                        // Notify event handlers
                        self.notify_event_handlers(ChannelEvent::ConfigChanged {
                            cid: local_cid,
                            config: options,
                        });
                    } else if flags & 0x0001 != 0 {
                        // Continuation flag set, need to send another request
                        // TODO: Handle continuation
                    } else {
                        // Configuration failed
                        // TODO: Handle failure
                    }
                },
                _ => {
                    return Err(L2capError::ProtocolError("Unexpected configure response".into()));
                }
            }
        } else {
            // No pending transaction for this response
            return Err(L2capError::ProtocolError("Unexpected configure response".into()));
        }
        
        Ok(())
    }
    
    /// Handle a disconnection request
    fn handle_disconnection_request(
        &self,
        identifier: u8,
        destination_cid: ChannelId,
        source_cid: ChannelId,
        hci_handle: u16
    ) -> L2capResult<()> {
        // Find the channel
        let (local_cid, psm) = {
            let mut channels = self.channels.write().unwrap();
            
            // Look for a channel with matching remote CID
            let mut found_channel = None;
            for (local_cid, channel) in channels.iter() {
                if *local_cid == destination_cid && channel.remote_cid() == source_cid {
                    found_channel = Some((*local_cid, channel.psm()));
                    break;
                }
            }
            
            found_channel.ok_or(L2capError::ChannelNotFound)?
        };
        
        // Send disconnection response
        let response = SignalingMessage::DisconnectionResponse {
            identifier,
            destination_cid,
            source_cid,
        };
        
        // Send the response (would be sent via HCI)
        
        // Remove the channel
        {
            let mut channels = self.channels.write().unwrap();
            channels.remove(&local_cid);
        }
        
        // Notify event handlers
        self.notify_event_handlers(ChannelEvent::Disconnected {
            cid: local_cid,
            psm,
            reason: "Remote disconnection".into(),
        });
        
        Ok(())
    }
    
    /// Handle a disconnection response
    fn handle_disconnection_response(
        &self,
        identifier: u8,
        destination_cid: ChannelId,
        source_cid: ChannelId
    ) -> L2capResult<()> {
        // Find the pending transaction
        let transaction = {
            let mut transactions = self.pending_transactions.write().unwrap();
            transactions.remove(&identifier)
        };
        
        if let Some(transaction) = transaction {
            match transaction.transaction_type {
                SignalingTransactionType::Disconnect(local_cid, remote_cid) => {
                    if local_cid != destination_cid || remote_cid != source_cid {
                        return Err(L2capError::InvalidParameter("Mismatched CIDs".into()));
                    }
                    
                    let psm = {
                        let channels = self.channels.read().unwrap();
                        channels.get(&local_cid).and_then(|c| c.psm())
                    };
                    
                    // Remove the channel
                    {
                        let mut channels = self.channels.write().unwrap();
                        channels.remove(&local_cid);
                    }
                    
                    // Notify event handlers
                    self.notify_event_handlers(ChannelEvent::Disconnected {
                        cid: local_cid,
                        psm,
                        reason: "Local disconnection".into(),
                    });
                },
                _ => {
                    return Err(L2capError::ProtocolError("Unexpected disconnection response".into()));
                }
            }
        } else {
            // No pending transaction for this response
            return Err(L2capError::ProtocolError("Unexpected disconnection response".into()));
        }
        
        Ok(())
    }
    
    /// Handle a connection parameter update request (LE only)
    fn handle_connection_parameter_update_request(
        &self,
        identifier: u8,
        params: ConnectionParameterUpdate,
        hci_handle: u16
    ) -> L2capResult<()> {
        if self.connection_type != ConnectionType::LE {
            return Err(L2capError::NotSupported);
        }
        
        // Validate the parameters
        if !params.validate() {
            // Reject the request
            let response = SignalingMessage::ConnectionParameterUpdateResponse {
                identifier,
                result: L2CAP_CONN_PARAM_UPDATE_REJECTED,
            };
            
            // Send the response (would be sent via HCI)
            
            return Ok(());
        }
        
        // Notify event handlers
        self.notify_event_handlers(ChannelEvent::ConnectionParameterUpdateRequest {
            identifier,
            params,
        });
        
        // The actual parameter update would be handled by the HCI layer
        // Here we just send a successful response
        let response = SignalingMessage::ConnectionParameterUpdateResponse {
            identifier,
            result: L2CAP_CONN_PARAM_UPDATE_ACCEPTED,
        };
        
        // Send the response (would be sent via HCI)
        
        Ok(())
    }
    
    /// Handle a connection parameter update response (LE only)
    fn handle_connection_parameter_update_response(
        &self,
        identifier: u8,
        result: u16
    ) -> L2capResult<()> {
        if self.connection_type != ConnectionType::LE {
            return Err(L2capError::NotSupported);
        }
        
        // Find the pending transaction
        let transaction = {
            let mut transactions = self.pending_transactions.write().unwrap();
            transactions.remove(&identifier)
        };
        
        if let Some(transaction) = transaction {
            match transaction.transaction_type {
                SignalingTransactionType::ConnectionParameterUpdate => {
                    // The actual parameter update would be handled by the HCI layer
                    // Here we just check the result
                    if result != L2CAP_CONN_PARAM_UPDATE_ACCEPTED {
                        // Update rejected
                        // TODO: Handle rejection
                    }
                },
                _ => {
                    return Err(L2capError::ProtocolError("Unexpected parameter update response".into()));
                }
            }
        } else {
            // No pending transaction for this response
            return Err(L2capError::ProtocolError("Unexpected parameter update response".into()));
        }
        
        Ok(())
    }
    
    /// Handle an LE Credit Based Connection Request
    fn handle_le_credit_based_connection_request(
        &self,
        identifier: u8,
        le_psm: u16,
        source_cid: ChannelId,
        mtu: u16,
        mps: u16,
        initial_credits: u16,
        hci_handle: u16
    ) -> L2capResult<()> {
        if self.connection_type != ConnectionType::LE {
            return Err(L2capError::NotSupported);
        }
        
        // Look up the PSM
        let psm = PSM::from_value(le_psm)
            .ok_or_else(|| L2capError::InvalidParameter(format!("Invalid PSM value: {}", le_psm)))?;
            
        // Check if PSM is registered
        let registration = {
            let registrations = self.psm_registrations.read().unwrap();
            
            registrations.get(&psm.value())
                .cloned()
                .ok_or(L2capError::PsmNotRegistered)?
        };
        
        // Allocate a local CID
        let local_cid = self.allocate_cid()?;
        
        // Create a new channel
        let mut channel = L2capChannel::new_le_credit_based(
            local_cid,
            psm,
            LeCreditBasedConfig {
                mtu,
                mps,
                initial_credits,
            },
        );
        channel.set_remote_cid(source_cid);
        
        // Set data callback if registered
        if let Some(ref callback) = registration.data_callback {
            channel.set_data_callback(move |data| {
                let mut callback = callback.lock().unwrap();
                (*callback)(data)
            });
        }
        
        // Add the channel to our map
        {
            let mut channels = self.channels.write().unwrap();
            channels.insert(local_cid, channel);
        }
        
        // Associate the channel with the HCI handle
        {
            let mut handle_map = self.handle_to_cid.write().unwrap();
            handle_map.entry(hci_handle).or_insert_with(Vec::new).push(local_cid);
        }
        
        // If the connection is auto-accepted, send response immediately
        if registration.auto_accept {
            // Send connection response
            let response = SignalingMessage::LeCreditBasedConnectionResponse {
                identifier,
                destination_cid: local_cid,
                mtu: L2CAP_LE_DEFAULT_MTU,
                mps: L2CAP_LE_DEFAULT_MTU,
                initial_credits: 10, // Default initial credits
                result: L2CAP_RESULT_SUCCESS,
            };
            
            // Update channel state
            {
                let mut channels = self.channels.write().unwrap();
                if let Some(channel) = channels.get_mut(&local_cid) {
                    channel.set_state(L2capChannelState::Open);
                }
            }
            
            // Send the response (would be sent via HCI)
            
            // Notify event handlers of connection
            self.notify_event_handlers(ChannelEvent::Connected {
                cid: local_cid,
                psm,
            });
        } else {
            // Let the application decide
            self.notify_event_handlers(ChannelEvent::ConnectionRequest {
                identifier,
                psm,
                source_cid,
            });
        }
        
        Ok(())
    }
    
    /// Handle an LE Credit Based Connection Response
    fn handle_le_credit_based_connection_response(
        &self,
        identifier: u8,
        destination_cid: ChannelId,
        mtu: u16,
        mps: u16,
        initial_credits: u16,
        result: u16
    ) -> L2capResult<()> {
        if self.connection_type != ConnectionType::LE {
            return Err(L2capError::NotSupported);
        }
        
        // Find the pending transaction
        let transaction = {
            let mut transactions = self.pending_transactions.write().unwrap();
            transactions.remove(&identifier)
        };
        
        if let Some(transaction) = transaction {
            match transaction.transaction_type {
                SignalingTransactionType::Connect(psm, local_cid) => {
                    if result == L2CAP_RESULT_SUCCESS {
                        // Connection successful
                        {
                            let mut channels = self.channels.write().unwrap();
                            if let Some(channel) = channels.get_mut(&local_cid) {
                                channel.set_remote_cid(destination_cid);
                                channel.set_remote_mtu(mtu);
                                // Set remote MPS and credits
                                channel.set_state(L2capChannelState::Open);
                            } else {
                                return Err(L2capError::ChannelNotFound);
                            }
                        }
                        
                        // Notify event handlers
                        self.notify_event_handlers(ChannelEvent::Connected {
                            cid: local_cid,
                            psm,
                        });
                    } else {
                        // Connection failed
                        {
                            let mut channels = self.channels.write().unwrap();
                            channels.remove(&local_cid);
                        }
                        
                        // Notify event handlers of disconnection
                        self.notify_event_handlers(ChannelEvent::Disconnected {
                            cid: local_cid,
                            psm: Some(psm),
                            reason: format!("Connection failed: result={}", result),
                        });
                    }
                },
                _ => {
                    return Err(L2capError::ProtocolError("Unexpected connection response".into()));
                }
            }
        } else {
            // No pending transaction for this response
            return Err(L2capError::ProtocolError("Unexpected connection response".into()));
        }
        
        Ok(())
    }
    
    /// Handle an LE Flow Control Credit
    fn handle_le_flow_control_credit(
        &self,
        identifier: u8,
        cid: ChannelId,
        credits: u16
    ) -> L2capResult<()> {
        if self.connection_type != ConnectionType::LE {
            return Err(L2capError::NotSupported);
        }
        
        // Find the channel (local_cid)
        let local_cid = {
            let channels = self.channels.read().unwrap();
            
            // Look for a channel with matching remote CID
            let mut found_cid = None;
            for (local_cid, channel) in channels.iter() {
                if channel.remote_cid() == cid {
                    found_cid = Some(*local_cid);
                    break;
                }
            }
            
            found_cid.ok_or(L2capError::ChannelNotFound)?
        };
        
        // Add the credits to the channel
        {
            let mut channels = self.channels.write().unwrap();
            if let Some(channel) = channels.get_mut(&local_cid) {
                channel.add_credits(credits)?;
            }
        }
        
        Ok(())
    }
    
    /// Send a command reject message
    fn send_command_reject(
        &self,
        identifier: u8,
        reason: u16,
        data: &[u8],
        hci_handle: u16
    ) -> L2capResult<()> {
        let message = SignalingMessage::CommandReject {
            identifier,
            reason,
            data: data.to_vec(),
        };
        
        // Send the message (would be sent via HCI)
        
        Ok(())
    }
    
    /// Notify event handlers of a channel event
    fn notify_event_handlers(&self, event: ChannelEvent) {
        // Check for PSM-specific event callback
        if let ChannelEvent::Connected { cid: _, psm } | ChannelEvent::ConnectionRequest { psm, .. } = &event {
            let registrations = self.psm_registrations.read().unwrap();
            if let Some(registration) = registrations.get(&psm.value()) {
                if let Some(ref callback) = registration.event_callback {
                    let mut callback = callback.lock().unwrap();
                    let _ = (*callback)(event.clone());
                    return;
                }
            }
        }
        
        // Fall back to global event callback
        let global_callback = self.global_event_callback.lock().unwrap();
        if let Some(ref callback) = *global_callback {
            let mut callback = callback.lock().unwrap();
            let _ = (*callback)(event);
        }
    }
    
    /// Process timeouts for pending transactions
    pub fn process_timeouts(&self, timeout: Duration) -> L2capResult<()> {
        let mut expired_transactions = Vec::new();
        
        {
            let mut transactions = self.pending_transactions.write().unwrap();
            
            // Find expired transactions
            for (id, transaction) in transactions.iter() {
                if transaction.timestamp.elapsed() > timeout {
                    expired_transactions.push(*id);
                }
            }
            
            // Remove expired transactions
            for id in &expired_transactions {
                transactions.remove(id);
            }
        }
        
        // Process each expired transaction
        for id in expired_transactions {
            // Handle the timeout for the specific transaction
            // For now, we'll just report a disconnection for connection requests
            
            // TODO: Implement retries and proper timeout handling
        }
        
        Ok(())
    }
    
    /// Remove channels associated with a disconnected HCI handle
    pub fn handle_connection_closed(&self, hci_handle: u16) -> L2capResult<()> {
        let cids = {
            let mut handle_map = self.handle_to_cid.write().unwrap();
            handle_map.remove(&hci_handle).unwrap_or_default()
        };
        
        for cid in cids {
            let psm = {
                let channels = self.channels.read().unwrap();
                channels.get(&cid).and_then(|c| c.psm())
            };
            
            // Remove the channel
            {
                let mut channels = self.channels.write().unwrap();
                channels.remove(&cid);
            }
            
            // Notify event handlers
            self.notify_event_handlers(ChannelEvent::Disconnected {
                cid,
                psm,
                reason: "HCI connection closed".into(),
            });
        }
        
        Ok(())
    }

    // Add placeholder for send_signaling_message if it was missing
    fn send_signaling_message(&self, _hci_handle: u16, _channel_id: ChannelId, message: SignalingMessage) -> L2capResult<()> {
         warn!("Sending signaling message (needs HCI integration): {:?}", message);
         Ok(())
    }
}
