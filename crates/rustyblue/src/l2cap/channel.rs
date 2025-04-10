//! L2CAP Channel implementation
//!
//! This module provides the L2CAP channel abstraction which represents 
//! a logical connection between two devices for a specific protocol or service.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::constants::*;
use super::types::*;
use super::packet::*;
use super::psm::PSM;
use super::signaling::SignalingMessage;

/// Callback for received data on an L2CAP channel
pub type DataCallback = Arc<Mutex<dyn FnMut(&[u8]) -> L2capResult<()> + Send + 'static>>;

/// Type of L2CAP channel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2capChannelType {
    /// Fixed signaling channel (CID 1 or 5)
    Signaling,
    /// Connectionless channel (CID 2)
    Connectionless,
    /// AMP Manager (CID 3)
    AmpManager,
    /// Attribute Protocol (ATT) channel (CID 4)
    AttributeProtocol,
    /// Security Manager Protocol (SMP) channel (CID 6)
    SecurityManager,
    /// Dynamically allocated connection-oriented channel
    ConnectionOriented,
    /// LE Credit-based connection-oriented channel
    LeCreditBased,
}

/// L2CAP Channel structure
pub struct L2capChannel {
    /// Local Channel Identifier (CID)
    local_cid: u16,
    /// Remote Channel Identifier (CID)
    remote_cid: u16,
    /// Protocol/Service Multiplexer for this channel
    psm: Option<PSM>,
    /// Channel state
    state: L2capChannelState,
    /// Channel type
    channel_type: L2capChannelType,
    /// Maximum Transmission Unit (MTU)
    mtu: u16,
    /// Remote device's MTU
    remote_mtu: u16,
    /// Quality of Service specification
    qos: Option<QosFlowSpec>,
    /// Configuration options
    config: ConfigOptions,
    /// Remote configuration options
    remote_config: ConfigOptions,
    /// Data callback
    data_callback: Option<DataCallback>,
    /// Connection type (Classic or LE)
    connection_type: ConnectionType,
    /// Credits (for LE Credit-based channels)
    credits: u16,
    /// Remote credits (for LE Credit-based channels)
    remote_credits: u16,
    /// Maximum PDU size (for LE Credit-based channels)
    mps: u16,
    /// Remote maximum PDU size (for LE Credit-based channels)
    remote_mps: u16,
    /// Last activity timestamp
    last_activity: Instant,
    /// Flush timeout (in milliseconds)
    flush_timeout: u16,
    /// Sequence number for last received I-frame
    last_received_seq: u8,
    /// Next expected sequence number
    expected_tx_seq: u8,
    /// Next sequence number to use for outgoing frames
    next_tx_seq: u8,
    /// Whether retransmission is enabled
    retransmission_enabled: bool,
    /// Segmentation and reassembly buffer
    reassembly_buffer: Option<(Vec<u8>, usize)>,
}

impl L2capChannel {
    /// Create a new L2CAP channel
    pub fn new(
        local_cid: u16, 
        channel_type: L2capChannelType, 
        connection_type: ConnectionType
    ) -> Self {
        let mtu = if connection_type == ConnectionType::LE {
            L2CAP_LE_DEFAULT_MTU
        } else {
            L2CAP_DEFAULT_MTU
        };
        
        Self {
            local_cid,
            remote_cid: 0,
            psm: None,
            state: L2capChannelState::Closed,
            channel_type,
            mtu,
            remote_mtu: mtu,
            qos: None,
            config: ConfigOptions::default(),
            remote_config: ConfigOptions::default(),
            data_callback: None,
            connection_type,
            credits: 0,
            remote_credits: 0,
            mps: mtu,
            remote_mps: mtu,
            last_activity: Instant::now(),
            flush_timeout: L2CAP_DEFAULT_FLUSH_TIMEOUT,
            last_received_seq: 0,
            expected_tx_seq: 0,
            next_tx_seq: 0,
            retransmission_enabled: false,
            reassembly_buffer: None,
        }
    }
    
    /// Create a new fixed channel
    pub fn new_fixed(
        local_cid: u16, 
        channel_type: L2capChannelType, 
        connection_type: ConnectionType
    ) -> Self {
        let mut channel = Self::new(local_cid, channel_type, connection_type);
        channel.remote_cid = local_cid; // Fixed channels have the same CID on both sides
        channel.state = L2capChannelState::Open; // Fixed channels are always open
        channel
    }
    
    /// Create a new dynamic channel for connection-oriented services
    pub fn new_dynamic(
        local_cid: u16, 
        psm: PSM, 
        connection_type: ConnectionType
    ) -> Self {
        let mut channel = Self::new(local_cid, L2capChannelType::ConnectionOriented, connection_type);
        channel.psm = Some(psm);
        channel
    }
    
    /// Create a new LE Credit-based channel
    pub fn new_le_credit_based(
        local_cid: u16, 
        psm: PSM, 
        config: LeCreditBasedConfig
    ) -> Self {
        let mut channel = Self::new(local_cid, L2capChannelType::LeCreditBased, ConnectionType::LE);
        channel.psm = Some(psm);
        channel.mtu = config.mtu;
        channel.mps = config.mps;
        channel.credits = config.initial_credits;
        channel
    }
    
    /// Get the local Channel Identifier (CID)
    pub fn local_cid(&self) -> u16 {
        self.local_cid
    }
    
    /// Get the remote Channel Identifier (CID)
    pub fn remote_cid(&self) -> u16 {
        self.remote_cid
    }
    
    /// Set the remote Channel Identifier (CID)
    pub fn set_remote_cid(&mut self, remote_cid: u16) {
        self.remote_cid = remote_cid;
    }
    
    /// Get the Protocol/Service Multiplexer (PSM)
    pub fn psm(&self) -> Option<PSM> {
        self.psm
    }
    
    /// Get the channel state
    pub fn state(&self) -> L2capChannelState {
        self.state
    }
    
    /// Set the channel state
    pub fn set_state(&mut self, state: L2capChannelState) {
        self.state = state;
    }
    
    /// Get the channel type
    pub fn channel_type(&self) -> L2capChannelType {
        self.channel_type
    }
    
    /// Get the Maximum Transmission Unit (MTU)
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
    
    /// Get the remote MTU
    pub fn remote_mtu(&self) -> u16 {
        self.remote_mtu
    }
    
    /// Set the remote MTU
    pub fn set_remote_mtu(&mut self, mtu: u16) {
        self.remote_mtu = mtu;
    }
    
    /// Get the effective MTU (minimum of local and remote)
    pub fn effective_mtu(&self) -> u16 {
        std::cmp::min(self.mtu, self.remote_mtu)
    }
    
    /// Set the data callback
    pub fn set_data_callback<F>(&mut self, callback: F)
    where
        F: FnMut(&[u8]) -> L2capResult<()> + Send + 'static
    {
        self.data_callback = Some(Arc::new(Mutex::new(callback)));
    }
    
    /// Clear the data callback
    pub fn clear_data_callback(&mut self) {
        self.data_callback = None;
    }
    
    /// Check if the channel is fixed
    pub fn is_fixed(&self) -> bool {
        match self.channel_type {
            L2capChannelType::Signaling |
            L2capChannelType::Connectionless |
            L2capChannelType::AmpManager |
            L2capChannelType::AttributeProtocol |
            L2capChannelType::SecurityManager => true,
            _ => false,
        }
    }
    
    /// Check if the channel uses retransmission mode
    pub fn uses_retransmission(&self) -> bool {
        self.retransmission_enabled
    }
    
    /// Handle configuration options
    pub fn configure(&mut self, options: &ConfigOptions) -> L2capResult<()> {
        // Update channel configuration based on received options
        if let Some(mtu) = options.mtu {
            self.remote_mtu = mtu;
        }
        
        if let Some(flush_timeout) = options.flush_timeout {
            self.flush_timeout = flush_timeout;
        }
        
        if let Some(qos) = options.qos {
            self.qos = Some(qos);
        }
        
        if let Some(rfc) = options.retransmission {
            match rfc.mode {
                RetransmissionMode::Basic => {
                    self.retransmission_enabled = false;
                },
                RetransmissionMode::Retransmission |
                RetransmissionMode::EnhancedRetransmission => {
                    self.retransmission_enabled = true;
                    // Initialize retransmission parameters
                    self.next_tx_seq = 0;
                    self.expected_tx_seq = 0;
                },
                RetransmissionMode::FlowControl => {
                    self.retransmission_enabled = false;
                    // Initialize flow control parameters
                },
                RetransmissionMode::Streaming => {
                    self.retransmission_enabled = false;
                    // Initialize streaming parameters
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle received data for this channel
    pub fn handle_data(&mut self, data: &[u8]) -> L2capResult<()> {
        self.last_activity = Instant::now();
        
        // If this channel uses retransmission, handle control field
        if self.retransmission_enabled && data.len() >= 2 {
            return self.handle_retransmission_data(data);
        }
        
        // If it's a regular channel, just pass the data to the callback
        if let Some(callback) = &self.data_callback {
            let mut callback = callback.lock().unwrap();
            (*callback)(data)
        } else {
            // No callback registered
            Ok(())
        }
    }
    
    /// Handle data for channels in retransmission mode
    fn handle_retransmission_data(&mut self, data: &[u8]) -> L2capResult<()> {
        if data.len() < 2 {
            return Err(L2capError::InvalidParameter("Retransmission data too short".into()));
        }
        
        // Parse control field
        let control = L2capControlField::parse(data)
            .ok_or_else(|| L2capError::InvalidParameter("Failed to parse control field".into()))?;
            
        let payload = &data[2..];
        
        if control.frame_type {
            // S-frame (supervisory)
            self.handle_s_frame(control)
        } else {
            // I-frame (information)
            self.handle_i_frame(control, payload)
        }
    }
    
    /// Handle Supervisory frame
    fn handle_s_frame(&mut self, control: L2capControlField) -> L2capResult<()> {
        // Update expected sequence based on received ReqSeq
        if control.req_seq != self.next_tx_seq {
            // Process acknowledgment
            self.next_tx_seq = control.req_seq;
        }
        
        match control.supervisory_function {
            0 => { // Receiver Ready (RR)
                // No specific action needed beyond updating sequence numbers
            },
            1 => { // Reject (REJ)
                // Handle rejection - would implement retransmission logic here
            },
            2 => { // Receiver Not Ready (RNR)
                // Peer is not ready to receive - would pause transmission
            },
            3 => { // Selective Reject (SREJ)
                // Selective retransmission - would implement retransmission of specific frame
            },
            _ => {
                return Err(L2capError::InvalidParameter(format!(
                    "Unknown supervisory function: {}", control.supervisory_function
                )));
            }
        }
        
        Ok(())
    }
    
    /// Handle Information frame
    fn handle_i_frame(&mut self, control: L2capControlField, payload: &[u8]) -> L2capResult<()> {
        // Check if this is the expected sequence number
        if control.tx_seq != self.expected_tx_seq {
            // Out of sequence frame - would implement appropriate handling here
            return Err(L2capError::ProtocolError(format!(
                "Unexpected sequence number: got {}, expected {}", 
                control.tx_seq, self.expected_tx_seq
            )));
        }
        
        // Update sequence tracking
        self.expected_tx_seq = (self.expected_tx_seq + 1) % 64;
        
        // Handle segmentation and reassembly
        match control.sar {
            0 => { // Unsegmented
                if let Some(callback) = &self.data_callback {
                    let mut callback = callback.lock().unwrap();
                    (*callback)(payload)?;
                }
            },
            1 => { // Start
                if payload.len() < 2 {
                    return Err(L2capError::InvalidParameter("SAR start too short".into()));
                }
                
                // First two bytes contain total SDU length
                let mut sdu_length = ((payload[1] as u16) << 8) | (payload[0] as u16);
                
                // Initialize reassembly buffer with the total length
                let mut buffer = Vec::with_capacity(sdu_length as usize);
                buffer.extend_from_slice(&payload[2..]);
                
                self.reassembly_buffer = Some((buffer, sdu_length as usize));
            },
            2 => { // End
                if let Some((ref mut buffer, total_length)) = self.reassembly_buffer {
                    // Add the final segment
                    buffer.extend_from_slice(payload);
                    
                    // Check if we've received the expected total length
                    if buffer.len() != total_length {
                        self.reassembly_buffer = None;
                        return Err(L2capError::ProtocolError(
                            "SDU length mismatch in reassembly".into()
                        ));
                    }
                    
                    // Send complete PDU to callback
                    if let Some(callback) = &self.data_callback {
                        let mut callback = callback.lock().unwrap();
                        (*callback)(buffer)?;
                    }
                    
                    // Clear the reassembly buffer
                    self.reassembly_buffer = None;
                } else {
                    return Err(L2capError::ProtocolError(
                        "Received END segment without START".into()
                    ));
                }
            },
            3 => { // Continuation
                if let Some((ref mut buffer, _)) = self.reassembly_buffer {
                    // Add continuation segment
                    buffer.extend_from_slice(payload);
                } else {
                    return Err(L2capError::ProtocolError(
                        "Received CONTINUATION segment without START".into()
                    ));
                }
            },
            _ => {
                return Err(L2capError::InvalidParameter(format!(
                    "Invalid SAR value: {}", control.sar
                )));
            }
        }
        
        Ok(())
    }
    
    /// Handle LE Credit-based flow control
    pub fn add_credits(&mut self, credits: u16) -> L2capResult<()> {
        if self.channel_type != L2capChannelType::LeCreditBased {
            return Err(L2capError::InvalidState);
        }
        
        // Prevent overflow
        if self.remote_credits > u16::MAX - credits {
            self.remote_credits = u16::MAX;
        } else {
            self.remote_credits += credits;
        }
        
        Ok(())
    }
    
    /// Consume credits when sending data
    pub fn consume_credits(&mut self, count: u16) -> L2capResult<()> {
        if self.channel_type != L2capChannelType::LeCreditBased {
            return Err(L2capError::InvalidState);
        }
        
        if self.remote_credits < count {
            return Err(L2capError::ResourceLimitReached);
        }
        
        self.remote_credits -= count;
        Ok(())
    }
    
    /// Create a data packet for this channel
    pub fn create_data_packet(&self, data: &[u8]) -> L2capResult<L2capPacket> {
        if self.state != L2capChannelState::Open {
            return Err(L2capError::InvalidState);
        }
        
        if self.remote_cid == 0 {
            return Err(L2capError::NotConnected);
        }
        
        // Check if data exceeds MTU
        if data.len() > self.remote_mtu as usize {
            return Err(L2capError::MtuExceeded);
        }
        
        // For LE Credit-based channels, check credits
        if self.channel_type == L2capChannelType::LeCreditBased && self.remote_credits == 0 {
            return Err(L2capError::ResourceLimitReached);
        }
        
        let packet = if self.retransmission_enabled {
            // Create packet with control field for retransmission mode
            let control = L2capControlField::new_i_frame(
                self.next_tx_seq,
                self.expected_tx_seq,
                false, // poll bit
                0,     // unsegmented
            );
            
            L2capPacket::new_with_control(self.remote_cid, control, data.to_vec())
        } else {
            // Create basic packet
            L2capPacket::new(self.remote_cid, data.to_vec())
        };
        
        Ok(packet)
    }
    
    /// Check if the channel is idle (no activity for a specific duration)
    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
    
    /// Update the last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

impl fmt::Debug for L2capChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L2capChannel")
            .field("local_cid", &self.local_cid)
            .field("remote_cid", &self.remote_cid)
            .field("psm", &self.psm)
            .field("state", &self.state)
            .field("channel_type", &self.channel_type)
            .field("mtu", &self.mtu)
            .field("remote_mtu", &self.remote_mtu)
            .field("connection_type", &self.connection_type)
            .field("retransmission_enabled", &self.retransmission_enabled)
            .field("has_callback", &self.data_callback.is_some())
            .finish()
    }
}