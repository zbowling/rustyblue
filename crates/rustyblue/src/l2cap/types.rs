//! Type definitions for L2CAP operations
//!
//! This module contains core data structures used in L2CAP operations.

use std::fmt;
use thiserror::Error;

/// Error types specific to L2CAP operations
#[derive(Debug, Error)]
pub enum L2capError {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Connection timeout")]
    Timeout,
    
    #[error("Remote device rejected connection: {0}")]
    ConnectionRejected(u16),
    
    #[error("Channel not found")]
    ChannelNotFound,
    
    #[error("Operation not supported")]
    NotSupported,
    
    #[error("Invalid state for operation")]
    InvalidState,
    
    #[error("MTU exceeded")]
    MtuExceeded,
    
    #[error("Resource limit reached")]
    ResourceLimitReached,
    
    #[error("PSM not registered")]
    PsmNotRegistered,
    
    #[error("Security requirements not met")]
    SecurityRequirementsNotMet,
    
    #[error("Connection terminated")]
    ConnectionTerminated,
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("HCI error: {0}")]
    HciError(#[from] crate::error::HciError),
    
    #[error("Connection not established")]
    NotConnected,
}

/// Result type for L2CAP operations
pub type L2capResult<T> = std::result::Result<T, L2capError>;

/// Quality of Service (QoS) Flow Specification
#[derive(Debug, Clone, Copy)]
pub struct QosFlowSpec {
    /// QoS service type
    pub service_type: u8,
    /// Token rate (bytes/second)
    pub token_rate: u32,
    /// Token bucket size (bytes)
    pub token_bucket_size: u32,
    /// Peak bandwidth (bytes/second)
    pub peak_bandwidth: u32,
    /// Latency (microseconds)
    pub latency: u32,
    /// Delay variation (microseconds)
    pub delay_variation: u32,
}

impl Default for QosFlowSpec {
    fn default() -> Self {
        Self {
            service_type: 0, // Best effort
            token_rate: 0,
            token_bucket_size: 0,
            peak_bandwidth: 0,
            latency: 0xFFFFFFFF,
            delay_variation: 0xFFFFFFFF,
        }
    }
}

/// L2CAP Configuration Options
#[derive(Debug, Clone)]
pub struct ConfigOptions {
    /// Maximum Transmission Unit
    pub mtu: Option<u16>,
    /// Flush Timeout
    pub flush_timeout: Option<u16>,
    /// Quality of Service
    pub qos: Option<QosFlowSpec>,
    /// Retransmission and Flow Control
    pub retransmission: Option<RetransmissionFlowControl>,
    /// Frame Check Sequence
    pub fcs: Option<u8>,
    /// Extended Flow Specification
    pub ext_flow_spec: Option<ExtendedFlowSpec>,
    /// Extended Window Size
    pub ext_window_size: Option<u16>,
}

impl Default for ConfigOptions {
    fn default() -> Self {
        Self {
            mtu: None,
            flush_timeout: None,
            qos: None,
            retransmission: None,
            fcs: None,
            ext_flow_spec: None,
            ext_window_size: None,
        }
    }
}

/// Retransmission and Flow Control modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetransmissionMode {
    /// Basic L2CAP mode (no retransmission or flow control)
    Basic = 0,
    /// Retransmission mode
    Retransmission = 1,
    /// Flow control mode
    FlowControl = 2,
    /// Enhanced Retransmission mode (preferred)
    EnhancedRetransmission = 3,
    /// Streaming mode
    Streaming = 4,
}

/// Retransmission and Flow Control configuration
#[derive(Debug, Clone, Copy)]
pub struct RetransmissionFlowControl {
    /// Mode selection
    pub mode: RetransmissionMode,
    /// Transmission Window size
    pub tx_window_size: u8,
    /// Maximum number of retransmissions
    pub max_retransmit: u8,
    /// Monitor timeout (ms)
    pub monitor_timeout: u16,
    /// Acknowledgment timeout (ms)
    pub retransmit_timeout: u16,
}

impl Default for RetransmissionFlowControl {
    fn default() -> Self {
        Self {
            mode: RetransmissionMode::Basic,
            tx_window_size: 0,
            max_retransmit: 0,
            monitor_timeout: 0,
            retransmit_timeout: 0,
        }
    }
}

/// Extended Flow Specification
#[derive(Debug, Clone, Copy)]
pub struct ExtendedFlowSpec {
    /// Identifier
    pub identifier: u8,
    /// Service type
    pub service_type: u8,
    /// Maximum SDU size
    pub max_sdu_size: u16,
    /// SDU inter-arrival time
    pub sdu_inter_arrival_time: u32,
    /// Access latency
    pub access_latency: u32,
    /// Flush timeout
    pub flush_timeout: u32,
}

/// L2CAP Channel State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2capChannelState {
    /// Channel is closed
    Closed,
    /// Channel is waiting for connection
    WaitConnectRsp,
    /// Channel is waiting for connection response
    WaitConfig,
    /// Channel is waiting for configuration
    WaitConfigReq,
    /// Channel is waiting for final configuration
    WaitFinalConfig,
    /// Channel is open and ready for data transfer
    Open,
    /// Channel is waiting for disconnection response
    WaitDisconnect,
}

impl fmt::Display for L2capChannelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "Closed"),
            Self::WaitConnectRsp => write!(f, "Waiting for connection response"),
            Self::WaitConfig => write!(f, "Waiting for configuration"),
            Self::WaitConfigReq => write!(f, "Waiting for configuration request"),
            Self::WaitFinalConfig => write!(f, "Waiting for final configuration"),
            Self::Open => write!(f, "Open"),
            Self::WaitDisconnect => write!(f, "Waiting for disconnection"),
        }
    }
}

/// Connection types for L2CAP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Classic Bluetooth connection (ACL)
    Classic,
    /// Bluetooth Low Energy connection (LE)
    LE,
}

/// L2CAP Connection Parameter Update request structure
#[derive(Debug, Clone, Copy)]
pub struct ConnectionParameterUpdate {
    /// Minimum connection interval (1.25ms units)
    pub conn_interval_min: u16,
    /// Maximum connection interval (1.25ms units)
    pub conn_interval_max: u16,
    /// Peripheral latency (number of events)
    pub conn_latency: u16,
    /// Connection supervision timeout (10ms units)
    pub supervision_timeout: u16,
}

impl ConnectionParameterUpdate {
    /// Validates that the parameters are within acceptable ranges
    pub fn validate(&self) -> bool {
        // Check individual ranges
        let interval_ok = self.conn_interval_min >= super::constants::L2CAP_LE_CONN_INTERVAL_MIN
            && self.conn_interval_max <= super::constants::L2CAP_LE_CONN_INTERVAL_MAX
            && self.conn_interval_min <= self.conn_interval_max;
            
        let latency_ok = self.conn_latency <= super::constants::L2CAP_LE_CONN_LATENCY_MAX;
        
        let timeout_ok = self.supervision_timeout >= super::constants::L2CAP_LE_SUPERVISION_TIMEOUT_MIN
            && self.supervision_timeout <= super::constants::L2CAP_LE_SUPERVISION_TIMEOUT_MAX;
            
        // Check the relationship between parameters
        // Supervision timeout must be larger than max interval * (latency + 1) * 2
        let relation_ok = (self.supervision_timeout as u32) > 
            ((self.conn_interval_max as u32) * (self.conn_latency as u32 + 1) * 2) / 10;
            
        interval_ok && latency_ok && timeout_ok && relation_ok
    }
}

/// LE Credit-Based Connection configuration
#[derive(Debug, Clone, Copy)]
pub struct LeCreditBasedConfig {
    /// Maximum Transmission Unit
    pub mtu: u16,
    /// Maximum PDU size
    pub mps: u16,
    /// Initial credits
    pub initial_credits: u16,
}

impl Default for LeCreditBasedConfig {
    fn default() -> Self {
        Self {
            mtu: super::constants::L2CAP_LE_DEFAULT_MTU,
            mps: super::constants::L2CAP_LE_DEFAULT_MTU,
            initial_credits: 0,
        }
    }
}

/// L2CAP Security Level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// No security (no authentication, no encryption)
    None = 0,
    /// Authentication required
    Authentication = 1,
    /// Authentication and encryption required
    AuthenticationAndEncryption = 2,
    /// Secure Connections required with encryption
    SecureConnectionsWithEncryption = 3,
}

/// L2CAP Connection Policy for determining when to allow connections
#[derive(Debug, Clone)]
pub struct ConnectionPolicy {
    /// Minimum required security level
    pub min_security_level: SecurityLevel,
    /// Whether authorization is required
    pub authorization_required: bool,
    /// Whether connections are auto-accepted
    pub auto_accept: bool,
}