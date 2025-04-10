//! L2CAP Signaling channel implementation
//!
//! This module handles L2CAP signaling operations, including connection 
//! management, configuration, and information requests.

use super::constants::*;
use super::types::*;
use super::packet::*;
use super::psm::PSM;
use std::convert::TryFrom;
use std::io::{Cursor, Read, Write};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// Handle for identifying signaling transactions
pub type SignalId = u8;

/// L2CAP Signaling message
#[derive(Debug, Clone)]
pub enum SignalingMessage {
    /// Command Reject
    CommandReject {
        identifier: SignalId,
        reason: u16,
        data: Vec<u8>,
    },
    
    /// Connection Request
    ConnectionRequest {
        identifier: SignalId,
        psm: PSM,
        source_cid: u16,
    },
    
    /// Connection Response
    ConnectionResponse {
        identifier: SignalId,
        destination_cid: u16,
        source_cid: u16,
        result: u16,
        status: u16,
    },
    
    /// Configuration Request
    ConfigureRequest {
        identifier: SignalId,
        destination_cid: u16,
        flags: u16,
        options: ConfigOptions,
    },
    
    /// Configuration Response
    ConfigureResponse {
        identifier: SignalId,
        source_cid: u16,
        flags: u16,
        result: u16,
        options: ConfigOptions,
    },
    
    /// Disconnection Request
    DisconnectionRequest {
        identifier: SignalId,
        destination_cid: u16,
        source_cid: u16,
    },
    
    /// Disconnection Response
    DisconnectionResponse {
        identifier: SignalId,
        destination_cid: u16,
        source_cid: u16,
    },
    
    /// Echo Request
    EchoRequest {
        identifier: SignalId,
        data: Vec<u8>,
    },
    
    /// Echo Response
    EchoResponse {
        identifier: SignalId,
        data: Vec<u8>,
    },
    
    /// Information Request
    InformationRequest {
        identifier: SignalId,
        info_type: u16,
    },
    
    /// Information Response
    InformationResponse {
        identifier: SignalId,
        info_type: u16,
        result: u16,
        data: Vec<u8>,
    },
    
    /// Connection Parameter Update Request (LE only)
    ConnectionParameterUpdateRequest {
        identifier: SignalId,
        params: ConnectionParameterUpdate,
    },
    
    /// Connection Parameter Update Response (LE only)
    ConnectionParameterUpdateResponse {
        identifier: SignalId,
        result: u16,
    },
    
    /// LE Credit Based Connection Request
    LeCreditBasedConnectionRequest {
        identifier: SignalId,
        le_psm: u16,
        source_cid: u16,
        mtu: u16,
        mps: u16,
        initial_credits: u16,
    },
    
    /// LE Credit Based Connection Response
    LeCreditBasedConnectionResponse {
        identifier: SignalId,
        destination_cid: u16,
        mtu: u16,
        mps: u16,
        initial_credits: u16,
        result: u16,
    },
    
    /// LE Flow Control Credit
    LeFlowControlCredit {
        identifier: SignalId,
        cid: u16,
        credits: u16,
    },
}

impl SignalingMessage {
    /// Get the identifier for this message
    pub fn get_identifier(&self) -> SignalId {
        match self {
            SignalingMessage::CommandReject { identifier, .. } => *identifier,
            SignalingMessage::ConnectionRequest { identifier, .. } => *identifier,
            SignalingMessage::ConnectionResponse { identifier, .. } => *identifier,
            SignalingMessage::ConfigureRequest { identifier, .. } => *identifier,
            SignalingMessage::ConfigureResponse { identifier, .. } => *identifier,
            SignalingMessage::DisconnectionRequest { identifier, .. } => *identifier,
            SignalingMessage::DisconnectionResponse { identifier, .. } => *identifier,
            SignalingMessage::InformationRequest { identifier, .. } => *identifier,
            SignalingMessage::InformationResponse { identifier, .. } => *identifier,
            SignalingMessage::EchoRequest { identifier, .. } => *identifier,
            SignalingMessage::EchoResponse { identifier, .. } => *identifier,
            SignalingMessage::LeCreditBasedConnectionRequest { identifier, .. } => *identifier,
            SignalingMessage::LeCreditBasedConnectionResponse { identifier, .. } => *identifier,
            SignalingMessage::LeFlowControlCredit { identifier, .. } => *identifier,
            _ => 0, // Default for any not covered
        }
    }
    /// Get the command code for this signaling message
    pub fn command_code(&self) -> u8 {
        match self {
            Self::CommandReject { .. } => L2CAP_COMMAND_REJECT,
            Self::ConnectionRequest { .. } => L2CAP_CONNECTION_REQUEST,
            Self::ConnectionResponse { .. } => L2CAP_CONNECTION_RESPONSE,
            Self::ConfigureRequest { .. } => L2CAP_CONFIGURE_REQUEST,
            Self::ConfigureResponse { .. } => L2CAP_CONFIGURE_RESPONSE,
            Self::DisconnectionRequest { .. } => L2CAP_DISCONNECTION_REQUEST,
            Self::DisconnectionResponse { .. } => L2CAP_DISCONNECTION_RESPONSE,
            Self::EchoRequest { .. } => L2CAP_ECHO_REQUEST,
            Self::EchoResponse { .. } => L2CAP_ECHO_RESPONSE,
            Self::InformationRequest { .. } => L2CAP_INFORMATION_REQUEST,
            Self::InformationResponse { .. } => L2CAP_INFORMATION_RESPONSE,
            Self::ConnectionParameterUpdateRequest { .. } => L2CAP_CONNECTION_PARAMETER_UPDATE_REQUEST,
            Self::ConnectionParameterUpdateResponse { .. } => L2CAP_CONNECTION_PARAMETER_UPDATE_RESPONSE,
            Self::LeCreditBasedConnectionRequest { .. } => L2CAP_LE_CREDIT_BASED_CONNECTION_REQUEST,
            Self::LeCreditBasedConnectionResponse { .. } => L2CAP_LE_CREDIT_BASED_CONNECTION_RESPONSE,
            Self::LeFlowControlCredit { .. } => L2CAP_LE_FLOW_CONTROL_CREDIT,
        }
    }
    
    /// Get the identifier for this signaling message
    pub fn identifier(&self) -> SignalId {
        match self {
            Self::CommandReject { identifier, .. } => *identifier,
            Self::ConnectionRequest { identifier, .. } => *identifier,
            Self::ConnectionResponse { identifier, .. } => *identifier,
            Self::ConfigureRequest { identifier, .. } => *identifier,
            Self::ConfigureResponse { identifier, .. } => *identifier,
            Self::DisconnectionRequest { identifier, .. } => *identifier,
            Self::DisconnectionResponse { identifier, .. } => *identifier,
            Self::EchoRequest { identifier, .. } => *identifier,
            Self::EchoResponse { identifier, .. } => *identifier,
            Self::InformationRequest { identifier, .. } => *identifier,
            Self::InformationResponse { identifier, .. } => *identifier,
            Self::ConnectionParameterUpdateRequest { identifier, .. } => *identifier,
            Self::ConnectionParameterUpdateResponse { identifier, .. } => *identifier,
            Self::LeCreditBasedConnectionRequest { identifier, .. } => *identifier,
            Self::LeCreditBasedConnectionResponse { identifier, .. } => *identifier,
            Self::LeFlowControlCredit { identifier, .. } => *identifier,
        }
    }
    
    /// Parse configuration options from raw bytes
    fn parse_config_options(data: &[u8]) -> ConfigOptions {
        let mut options = ConfigOptions::default();
        let mut offset = 0;
        
        while offset + 2 <= data.len() {
            let option_type = data[offset] & 0x7F; // Mask out hint bit
            let option_length = data[offset + 1];
            
            // Ensure we have enough data for this option
            if offset + 2 + option_length as usize > data.len() {
                break;
            }
            
            let option_data = &data[offset + 2..offset + 2 + option_length as usize];
            
            match option_type {
                L2CAP_CONF_MTU => {
                    if option_length == 2 {
                        let mut cursor = Cursor::new(option_data);
                        if let Ok(mtu) = cursor.read_u16::<LittleEndian>() {
                            options.mtu = Some(mtu);
                        }
                    }
                },
                L2CAP_CONF_FLUSH_TIMEOUT => {
                    if option_length == 2 {
                        let mut cursor = Cursor::new(option_data);
                        if let Ok(timeout) = cursor.read_u16::<LittleEndian>() {
                            options.flush_timeout = Some(timeout);
                        }
                    }
                },
                L2CAP_CONF_QOS => {
                    if option_length == 22 {
                        // Parse QoS flow spec
                        let service_type = option_data[0];
                        let mut cursor = Cursor::new(&option_data[1..]);
                        
                        if let (Ok(token_rate), Ok(token_bucket_size), Ok(peak_bandwidth), 
                                 Ok(latency), Ok(delay_variation)) = (
                            cursor.read_u32::<LittleEndian>(),
                            cursor.read_u32::<LittleEndian>(),
                            cursor.read_u32::<LittleEndian>(),
                            cursor.read_u32::<LittleEndian>(),
                            cursor.read_u32::<LittleEndian>()
                        ) {
                            options.qos = Some(QosFlowSpec {
                                service_type,
                                token_rate,
                                token_bucket_size,
                                peak_bandwidth,
                                latency,
                                delay_variation,
                            });
                        }
                    }
                },
                L2CAP_CONF_RFC => {
                    if option_length >= 3 {
                        // Parse retransmission & flow control
                        let mode = match option_data[0] {
                            0 => RetransmissionMode::Basic,
                            1 => RetransmissionMode::Retransmission,
                            2 => RetransmissionMode::FlowControl,
                            3 => RetransmissionMode::EnhancedRetransmission,
                            4 => RetransmissionMode::Streaming,
                            _ => RetransmissionMode::Basic,
                        };
                        
                        let mut rfc = RetransmissionFlowControl {
                            mode,
                            ..Default::default()
                        };
                        
                        if option_data.len() >= 9 && 
                           (mode == RetransmissionMode::Retransmission || 
                            mode == RetransmissionMode::EnhancedRetransmission) {
                            rfc.tx_window_size = option_data[1];
                            rfc.max_retransmit = option_data[2];
                            
                            let mut cursor = Cursor::new(&option_data[3..]);
                            if let (Ok(monitor), Ok(retransmit)) = (
                                cursor.read_u16::<LittleEndian>(),
                                cursor.read_u16::<LittleEndian>()
                            ) {
                                rfc.monitor_timeout = monitor;
                                rfc.retransmit_timeout = retransmit;
                            }
                        } else if option_data.len() >= 5 && mode == RetransmissionMode::FlowControl {
                            rfc.tx_window_size = option_data[1];
                            
                            let mut cursor = Cursor::new(&option_data[2..]);
                            if let Ok(retransmit) = cursor.read_u16::<LittleEndian>() {
                                rfc.retransmit_timeout = retransmit;
                            }
                        }
                        
                        options.retransmission = Some(rfc);
                    }
                },
                L2CAP_CONF_FCS => {
                    if option_length == 1 {
                        options.fcs = Some(option_data[0]);
                    }
                },
                L2CAP_CONF_EXT_WINDOW => {
                    if option_length == 2 {
                        let mut cursor = Cursor::new(option_data);
                        if let Ok(window) = cursor.read_u16::<LittleEndian>() {
                            options.ext_window_size = Some(window);
                        }
                    }
                },
                // TODO: Handle other config options
                _ => {}
            }
            
            offset += 2 + option_length as usize;
        }
        
        options
    }
    
    /// Serialize configuration options to bytes
    fn serialize_config_options(options: &ConfigOptions) -> Vec<u8> {
        let mut result = Vec::new();
        
        // MTU option
        if let Some(mtu) = options.mtu {
            result.push(L2CAP_CONF_MTU);
            result.push(2); // Length
            result.extend_from_slice(&mtu.to_le_bytes());
        }
        
        // Flush timeout option
        if let Some(timeout) = options.flush_timeout {
            result.push(L2CAP_CONF_FLUSH_TIMEOUT);
            result.push(2); // Length
            result.extend_from_slice(&timeout.to_le_bytes());
        }
        
        // QoS option
        if let Some(qos) = options.qos {
            result.push(L2CAP_CONF_QOS);
            result.push(22); // Length
            result.push(qos.service_type);
            result.extend_from_slice(&qos.token_rate.to_le_bytes());
            result.extend_from_slice(&qos.token_bucket_size.to_le_bytes());
            result.extend_from_slice(&qos.peak_bandwidth.to_le_bytes());
            result.extend_from_slice(&qos.latency.to_le_bytes());
            result.extend_from_slice(&qos.delay_variation.to_le_bytes());
        }
        
        // Retransmission & flow control option
        if let Some(rfc) = options.retransmission {
            result.push(L2CAP_CONF_RFC);
            
            match rfc.mode {
                RetransmissionMode::Basic => {
                    result.push(1); // Length
                    result.push(0); // Mode
                },
                RetransmissionMode::Retransmission | 
                RetransmissionMode::EnhancedRetransmission => {
                    result.push(9); // Length
                    result.push(rfc.mode as u8); // Mode
                    result.push(rfc.tx_window_size);
                    result.push(rfc.max_retransmit);
                    result.extend_from_slice(&rfc.monitor_timeout.to_le_bytes());
                    result.extend_from_slice(&rfc.retransmit_timeout.to_le_bytes());
                },
                RetransmissionMode::FlowControl => {
                    result.push(5); // Length
                    result.push(2); // Mode
                    result.push(rfc.tx_window_size);
                    result.extend_from_slice(&rfc.retransmit_timeout.to_le_bytes());
                },
                RetransmissionMode::Streaming => {
                    result.push(1); // Length
                    result.push(4); // Mode
                },
            }
        }
        
        // FCS option
        if let Some(fcs) = options.fcs {
            result.push(L2CAP_CONF_FCS);
            result.push(1); // Length
            result.push(fcs);
        }
        
        // Extended window size option
        if let Some(window) = options.ext_window_size {
            result.push(L2CAP_CONF_EXT_WINDOW);
            result.push(2); // Length
            result.extend_from_slice(&window.to_le_bytes());
        }
        
        // TODO: Add other config options
        
        result
    }
    
    /// Parse a signaling message from raw bytes
    pub fn parse(data: &[u8], is_le: bool) -> Result<Self, L2capError> {
        if data.len() < 4 {
            return Err(L2capError::InvalidParameter("Signaling data too short".into()));
        }
        
        let cmd_header = L2capCommandHeader::parse(data)
            .ok_or_else(|| L2capError::InvalidParameter("Failed to parse command header".into()))?;
            
        let params = &data[4..];
        
        if params.len() < cmd_header.length as usize {
            return Err(L2capError::InvalidParameter("Command parameters too short".into()));
        }
        
        match cmd_header.code {
            L2CAP_COMMAND_REJECT => {
                if params.len() < 2 {
                    return Err(L2capError::InvalidParameter("Command reject parameters too short".into()));
                }
                
                let mut cursor = Cursor::new(&params[0..2]);
                let reason = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read reason".into()))?;
                    
                let data = params[2..].to_vec();
                
                Ok(Self::CommandReject {
                    identifier: cmd_header.identifier,
                    reason,
                    data,
                })
            },
            
            L2CAP_CONNECTION_REQUEST => {
                if params.len() < 4 {
                    return Err(L2capError::InvalidParameter("Connection request parameters too short".into()));
                }
                
                let mut cursor = Cursor::new(&params[0..2]);
                let psm_val = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read PSM".into()))?;
                    
                let psm = PSM::from_value(psm_val)
                    .ok_or_else(|| L2capError::InvalidParameter(format!("Invalid PSM value: {}", psm_val)))?;
                    
                let mut cursor = Cursor::new(&params[2..4]);
                let source_cid = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read source CID".into()))?;
                    
                Ok(Self::ConnectionRequest {
                    identifier: cmd_header.identifier,
                    psm,
                    source_cid,
                })
            },
            
            L2CAP_CONNECTION_RESPONSE => {
                if params.len() < 8 {
                    return Err(L2capError::InvalidParameter("Connection response parameters too short".into()));
                }
                
                let mut cursor = Cursor::new(&params[0..2]);
                let destination_cid = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read destination CID".into()))?;
                    
                let mut cursor = Cursor::new(&params[2..4]);
                let source_cid = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read source CID".into()))?;
                    
                let mut cursor = Cursor::new(&params[4..6]);
                let result = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read result".into()))?;
                    
                let mut cursor = Cursor::new(&params[6..8]);
                let status = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read status".into()))?;
                    
                Ok(Self::ConnectionResponse {
                    identifier: cmd_header.identifier,
                    destination_cid,
                    source_cid,
                    result,
                    status,
                })
            },
            
            L2CAP_CONFIGURE_REQUEST => {
                if params.len() < 4 {
                    return Err(L2capError::InvalidParameter("Configure request parameters too short".into()));
                }
                
                let mut cursor = Cursor::new(&params[0..2]);
                let destination_cid = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read destination CID".into()))?;
                    
                let mut cursor = Cursor::new(&params[2..4]);
                let flags = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read flags".into()))?;
                    
                let options = if params.len() > 4 {
                    Self::parse_config_options(&params[4..])
                } else {
                    ConfigOptions::default()
                };
                
                Ok(Self::ConfigureRequest {
                    identifier: cmd_header.identifier,
                    destination_cid,
                    flags,
                    options,
                })
            },
            
            L2CAP_CONFIGURE_RESPONSE => {
                if params.len() < 6 {
                    return Err(L2capError::InvalidParameter("Configure response parameters too short".into()));
                }
                
                let mut cursor = Cursor::new(&params[0..2]);
                let source_cid = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read source CID".into()))?;
                    
                let mut cursor = Cursor::new(&params[2..4]);
                let flags = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read flags".into()))?;
                    
                let mut cursor = Cursor::new(&params[4..6]);
                let result = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read result".into()))?;
                    
                let options = if params.len() > 6 {
                    Self::parse_config_options(&params[6..])
                } else {
                    ConfigOptions::default()
                };
                
                Ok(Self::ConfigureResponse {
                    identifier: cmd_header.identifier,
                    source_cid,
                    flags,
                    result,
                    options,
                })
            },
            
            L2CAP_DISCONNECTION_REQUEST => {
                if params.len() < 4 {
                    return Err(L2capError::InvalidParameter("Disconnection request parameters too short".into()));
                }
                
                let mut cursor = Cursor::new(&params[0..2]);
                let destination_cid = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read destination CID".into()))?;
                    
                let mut cursor = Cursor::new(&params[2..4]);
                let source_cid = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read source CID".into()))?;
                    
                Ok(Self::DisconnectionRequest {
                    identifier: cmd_header.identifier,
                    destination_cid,
                    source_cid,
                })
            },
            
            L2CAP_DISCONNECTION_RESPONSE => {
                if params.len() < 4 {
                    return Err(L2capError::InvalidParameter("Disconnection response parameters too short".into()));
                }
                
                let mut cursor = Cursor::new(&params[0..2]);
                let destination_cid = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read destination CID".into()))?;
                    
                let mut cursor = Cursor::new(&params[2..4]);
                let source_cid = cursor.read_u16::<LittleEndian>()
                    .map_err(|_| L2capError::InvalidParameter("Failed to read source CID".into()))?;
                    
                Ok(Self::DisconnectionResponse {
                    identifier: cmd_header.identifier,
                    destination_cid,
                    source_cid,
                })
            },
            
            // More message types to implement...
            // TODO: Implement remaining message parsing
            
            _ => Err(L2capError::NotSupported),
        }
    }
    
    /// Serialize the signaling message to bytes for transmission
    pub fn serialize(&self) -> Vec<u8> {
        let code = self.command_code();
        let identifier = self.identifier();
        
        let mut params = match self {
            Self::CommandReject { reason, data, .. } => {
                let mut params = Vec::with_capacity(2 + data.len());
                params.extend_from_slice(&reason.to_le_bytes());
                params.extend_from_slice(data);
                params
            },
            
            Self::ConnectionRequest { psm, source_cid, .. } => {
                let mut params = Vec::with_capacity(4);
                params.extend_from_slice(&psm.value().to_le_bytes());
                params.extend_from_slice(&source_cid.to_le_bytes());
                params
            },
            
            Self::ConnectionResponse { destination_cid, source_cid, result, status, .. } => {
                let mut params = Vec::with_capacity(8);
                params.extend_from_slice(&destination_cid.to_le_bytes());
                params.extend_from_slice(&source_cid.to_le_bytes());
                params.extend_from_slice(&result.to_le_bytes());
                params.extend_from_slice(&status.to_le_bytes());
                params
            },
            
            Self::ConfigureRequest { destination_cid, flags, options, .. } => {
                let option_bytes = Self::serialize_config_options(options);
                let mut params = Vec::with_capacity(4 + option_bytes.len());
                params.extend_from_slice(&destination_cid.to_le_bytes());
                params.extend_from_slice(&flags.to_le_bytes());
                params.extend_from_slice(&option_bytes);
                params
            },
            
            Self::ConfigureResponse { source_cid, flags, result, options, .. } => {
                let option_bytes = Self::serialize_config_options(options);
                let mut params = Vec::with_capacity(6 + option_bytes.len());
                params.extend_from_slice(&source_cid.to_le_bytes());
                params.extend_from_slice(&flags.to_le_bytes());
                params.extend_from_slice(&result.to_le_bytes());
                params.extend_from_slice(&option_bytes);
                params
            },
            
            Self::DisconnectionRequest { destination_cid, source_cid, .. } => {
                let mut params = Vec::with_capacity(4);
                params.extend_from_slice(&destination_cid.to_le_bytes());
                params.extend_from_slice(&source_cid.to_le_bytes());
                params
            },
            
            Self::DisconnectionResponse { destination_cid, source_cid, .. } => {
                let mut params = Vec::with_capacity(4);
                params.extend_from_slice(&destination_cid.to_le_bytes());
                params.extend_from_slice(&source_cid.to_le_bytes());
                params
            },
            
            Self::EchoRequest { data, .. } | Self::EchoResponse { data, .. } => {
                data.clone()
            },
            
            Self::InformationRequest { info_type, .. } => {
                let mut params = Vec::with_capacity(2);
                params.extend_from_slice(&info_type.to_le_bytes());
                params
            },
            
            Self::InformationResponse { info_type, result, data, .. } => {
                let mut params = Vec::with_capacity(4 + data.len());
                params.extend_from_slice(&info_type.to_le_bytes());
                params.extend_from_slice(&result.to_le_bytes());
                params.extend_from_slice(data);
                params
            },
            
            Self::ConnectionParameterUpdateRequest { params: conn_params, .. } => {
                let mut params = Vec::with_capacity(8);
                params.extend_from_slice(&conn_params.conn_interval_min.to_le_bytes());
                params.extend_from_slice(&conn_params.conn_interval_max.to_le_bytes());
                params.extend_from_slice(&conn_params.conn_latency.to_le_bytes());
                params.extend_from_slice(&conn_params.supervision_timeout.to_le_bytes());
                params
            },
            
            Self::ConnectionParameterUpdateResponse { result, .. } => {
                let mut params = Vec::with_capacity(2);
                params.extend_from_slice(&result.to_le_bytes());
                params
            },
            
            Self::LeCreditBasedConnectionRequest { le_psm, source_cid, mtu, mps, initial_credits, .. } => {
                let mut params = Vec::with_capacity(10);
                params.extend_from_slice(&le_psm.to_le_bytes());
                params.extend_from_slice(&source_cid.to_le_bytes());
                params.extend_from_slice(&mtu.to_le_bytes());
                params.extend_from_slice(&mps.to_le_bytes());
                params.extend_from_slice(&initial_credits.to_le_bytes());
                params
            },
            
            Self::LeCreditBasedConnectionResponse { destination_cid, mtu, mps, initial_credits, result, .. } => {
                let mut params = Vec::with_capacity(10);
                params.extend_from_slice(&destination_cid.to_le_bytes());
                params.extend_from_slice(&mtu.to_le_bytes());
                params.extend_from_slice(&mps.to_le_bytes());
                params.extend_from_slice(&initial_credits.to_le_bytes());
                params.extend_from_slice(&result.to_le_bytes());
                params
            },
            
            Self::LeFlowControlCredit { cid, credits, .. } => {
                let mut params = Vec::with_capacity(4);
                params.extend_from_slice(&cid.to_le_bytes());
                params.extend_from_slice(&credits.to_le_bytes());
                params
            },
        };
        
        let length = params.len() as u16;
        let cmd_header = L2capCommandHeader::new(code, identifier, length);
        
        let mut result = Vec::with_capacity(4 + params.len());
        result.extend_from_slice(&cmd_header.to_bytes());
        result.append(&mut params);
        
        result
    }
    
    /// Create a signaling L2CAP packet from this message
    pub fn to_packet(&self, is_le: bool) -> L2capPacket {
        let payload = self.serialize();
        let channel_id = if is_le { L2CAP_LE_SIGNALING_CID } else { L2CAP_SIGNALING_CID };
        
        L2capPacket::new(channel_id, payload)
    }
}