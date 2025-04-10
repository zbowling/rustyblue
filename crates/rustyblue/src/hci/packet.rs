//! HCI packet structures and parsing
//!
//! This module contains structures and methods for handling HCI packets.

use crate::hci::constants::*;

/// HCI command header structure
#[repr(C, packed)]
pub struct HciCommandHeader {
    opcode: u16,
    param_len: u8,
}

/// Common HCI Commands
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HciCommand {
    // Link Control Commands (OGF: 0x01)
    Inquiry,
    InquiryCancel,
    CreateConnection { bd_addr: [u8; 6], packet_type: u16 },
    Disconnect { handle: u16, reason: u8 },
    
    // Link Policy Commands (OGF: 0x02)
    SniffMode { handle: u16, max_interval: u16, min_interval: u16 },
    ExitSniffMode { handle: u16 },
    
    // Host Controller Commands (OGF: 0x03)
    Reset,
    SetEventMask { event_mask: u64 },
    
    // LE Commands (OGF: 0x08)
    LeSetScanParameters {
        scan_type: u8,
        scan_interval: u16,
        scan_window: u16,
        own_address_type: u8,
        filter_policy: u8,
    },
    LeSetScanEnable { enable: bool, filter_duplicates: bool },
    LeCreateConnection {
        peer_addr: [u8; 6],
        peer_addr_type: u8,
    },
    LeCreateConnectionCancel,
}

impl HciCommand {
    /// Get the OGF and OCF for this command
    pub fn opcode_parts(&self) -> (u8, u16) {
        match self {
            // Link Control Commands
            Self::Inquiry => (OGF_LINK_CTL, OCF_INQUIRY),
            Self::InquiryCancel => (OGF_LINK_CTL, OCF_INQUIRY_CANCEL),
            Self::CreateConnection { .. } => (OGF_LINK_CTL, OCF_CREATE_CONNECTION),
            Self::Disconnect { .. } => (OGF_LINK_CTL, OCF_DISCONNECT),
            
            // Link Policy Commands
            Self::SniffMode { .. } => (OGF_LINK_POLICY, OCF_SNIFF_MODE),
            Self::ExitSniffMode { .. } => (OGF_LINK_POLICY, OCF_EXIT_SNIFF_MODE),
            
            // Host Controller Commands
            Self::Reset => (OGF_HOST_CTL, OCF_RESET),
            Self::SetEventMask { .. } => (OGF_HOST_CTL, OCF_SET_EVENT_MASK),
            
            // LE Commands
            Self::LeSetScanParameters { .. } => (OGF_LE, OCF_LE_SET_SCAN_PARAMETERS),
            Self::LeSetScanEnable { .. } => (OGF_LE, OCF_LE_SET_SCAN_ENABLE),
            Self::LeCreateConnection { .. } => (OGF_LE, OCF_LE_CREATE_CONNECTION),
            Self::LeCreateConnectionCancel => (OGF_LE, OCF_LE_CREATE_CONNECTION_CANCEL),
        }
    }

    /// Convert the command to its raw parameter bytes
    fn parameters(&self) -> Vec<u8> {
        match *self {
            Self::Inquiry | Self::InquiryCancel | Self::Reset | Self::LeCreateConnectionCancel => vec![],
            
            Self::CreateConnection { bd_addr, packet_type } => {
                let mut params = Vec::with_capacity(8);
                params.extend_from_slice(&bd_addr);
                params.extend_from_slice(&packet_type.to_le_bytes());
                params
            }
            
            Self::Disconnect { handle, reason } => {
                let mut params = Vec::with_capacity(3);
                params.extend_from_slice(&handle.to_le_bytes());
                params.push(reason);
                params
            }
            
            Self::SniffMode { handle, max_interval, min_interval } => {
                let mut params = Vec::with_capacity(6);
                params.extend_from_slice(&handle.to_le_bytes());
                params.extend_from_slice(&max_interval.to_le_bytes());
                params.extend_from_slice(&min_interval.to_le_bytes());
                params
            }
            
            Self::ExitSniffMode { handle } => {
                handle.to_le_bytes().to_vec()
            }
            
            Self::SetEventMask { event_mask } => {
                event_mask.to_le_bytes().to_vec()
            }
            
            Self::LeSetScanParameters { scan_type, scan_interval, scan_window, own_address_type, filter_policy } => {
                let mut params = Vec::with_capacity(7);
                params.push(scan_type);
                params.extend_from_slice(&scan_interval.to_le_bytes());
                params.extend_from_slice(&scan_window.to_le_bytes());
                params.push(own_address_type);
                params.push(filter_policy);
                params
            }
            
            Self::LeSetScanEnable { enable, filter_duplicates } => {
                vec![enable as u8, filter_duplicates as u8]
            }
            
            Self::LeCreateConnection { peer_addr, peer_addr_type } => {
                let mut params = Vec::with_capacity(7);
                params.extend_from_slice(&peer_addr);
                params.push(peer_addr_type);
                params
            }
        }
    }

    /// Convert the command to a raw HCI packet
    pub fn to_packet(&self) -> Vec<u8> {
        let (ogf, ocf) = self.opcode_parts();
        let opcode = ((ogf as u16) << 10) | (ocf & 0x3ff);
        let params = self.parameters();
        
        let mut packet = vec![HCI_COMMAND_PKT];
        packet.extend_from_slice(&opcode.to_le_bytes());
        packet.push(params.len() as u8);
        packet.extend_from_slice(&params);
        packet
    }
}

/// HCI Event packet
#[derive(Debug, Clone)]
pub struct HciEvent {
    pub event_code: u8,
    pub parameter_total_length: u8,
    pub parameters: Vec<u8>,
}

impl HciEvent {
    /// Parse an HCI event from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        
        let event_code = data[0];
        let parameter_total_length = data[1];
        
        if data.len() < (parameter_total_length as usize + 2) {
            return None;
        }
        
        let parameters = data[2..(parameter_total_length as usize + 2)].to_vec();
        
        Some(HciEvent {
            event_code,
            parameter_total_length,
            parameters,
        })
    }
}

/// LE Advertising Report Event
#[derive(Debug, Clone)]
pub struct LeAdvertisingReport {
    pub event_type: u8,
    pub address_type: u8,
    pub address: [u8; 6],
    pub data_length: u8,
    pub data: Vec<u8>,
    pub rssi: i8,
}

impl LeAdvertisingReport {
    /// Parse an LE Advertising Report from an HCI LE Meta Event
    pub fn parse_from_meta_event(event: &HciEvent) -> Option<Self> {
        if event.event_code != EVT_LE_META_EVENT || event.parameters.is_empty() {
            return None;
        }
        
        let subevent_code = event.parameters[0];
        if subevent_code != EVT_LE_ADVERTISING_REPORT {
            return None;
        }
        
        // Simple parsing for a single report
        if event.parameters.len() < 12 {
            return None;
        }
        
        let event_type = event.parameters[2];
        let address_type = event.parameters[3];
        
        let mut address = [0u8; 6];
        address.copy_from_slice(&event.parameters[4..10]);
        
        let data_length = event.parameters[10];
        if event.parameters.len() < (11 + data_length as usize + 1) {
            return None;
        }
        
        let data = event.parameters[11..(11 + data_length as usize)].to_vec();
        let rssi = event.parameters[11 + data_length as usize] as i8;
        
        Some(LeAdvertisingReport {
            event_type,
            address_type,
            address,
            data_length,
            data,
            rssi,
        })
    }
}
