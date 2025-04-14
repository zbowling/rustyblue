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
    CreateConnection {
        bd_addr: [u8; 6],
        packet_type: u16,
    },
    Disconnect {
        handle: u16,
        reason: u8,
    },

    // Link Policy Commands (OGF: 0x02)
    SniffMode {
        handle: u16,
        max_interval: u16,
        min_interval: u16,
    },
    ExitSniffMode {
        handle: u16,
    },

    // Host Controller Commands (OGF: 0x03)
    Reset,
    SetEventMask {
        event_mask: u64,
    },

    // LE Commands (OGF: 0x08)
    LeSetEventMask {
        event_mask: u64,
    },
    LeReadBufferSize,
    LeReadLocalSupportedFeatures,
    LeSetRandomAddress {
        address: [u8; 6],
    },
    LeSetAdvertisingParameters {
        min_interval: u16,
        max_interval: u16,
        advertising_type: u8,
        own_address_type: u8,
        peer_address_type: u8,
        peer_address: [u8; 6],
        channel_map: u8,
        filter_policy: u8,
    },
    LeReadAdvertisingPhysicalChannelTxPower,
    LeSetAdvertisingData {
        data: Vec<u8>,
    },
    LeSetScanResponseData {
        data: Vec<u8>,
    },
    LeSetAdvertisingEnable {
        enable: bool,
    },
    LeSetScanParameters {
        scan_type: u8,
        scan_interval: u16,
        scan_window: u16,
        own_address_type: u8,
        filter_policy: u8,
    },
    LeSetScanEnable {
        enable: bool,
        filter_duplicates: bool,
    },
    LeCreateConnection {
        peer_addr: [u8; 6],
        peer_addr_type: u8,
        own_address_type: u8,
        conn_interval_min: u16,
        conn_interval_max: u16,
        conn_latency: u16,
        supervision_timeout: u16,
        min_ce_length: u16,
        max_ce_length: u16,
    },
    LeCreateConnectionCancel,

    // Raw command
    Raw {
        ogf: u8,
        ocf: u16,
        parameters: Vec<u8>,
    },
}

impl HciCommand {
    /// Create a new raw HCI command
    pub fn new(ogf: u8, ocf: u16, parameters: Vec<u8>) -> Self {
        Self::Raw {
            ogf,
            ocf,
            parameters,
        }
    }

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
            Self::LeSetEventMask { .. } => (OGF_LE, OCF_LE_SET_EVENT_MASK),
            Self::LeReadBufferSize => (OGF_LE, OCF_LE_READ_BUFFER_SIZE),
            Self::LeReadLocalSupportedFeatures => (OGF_LE, OCF_LE_READ_LOCAL_SUPPORTED_FEATURES),
            Self::LeSetRandomAddress { .. } => (OGF_LE, OCF_LE_SET_RANDOM_ADDRESS),
            Self::LeSetAdvertisingParameters { .. } => (OGF_LE, OCF_LE_SET_ADVERTISING_PARAMETERS),
            Self::LeReadAdvertisingPhysicalChannelTxPower => {
                (OGF_LE, OCF_LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER)
            }
            Self::LeSetAdvertisingData { .. } => (OGF_LE, OCF_LE_SET_ADVERTISING_DATA),
            Self::LeSetScanResponseData { .. } => (OGF_LE, OCF_LE_SET_SCAN_RESPONSE_DATA),
            Self::LeSetAdvertisingEnable { .. } => (OGF_LE, OCF_LE_SET_ADVERTISING_ENABLE),
            Self::LeSetScanParameters { .. } => (OGF_LE, OCF_LE_SET_SCAN_PARAMETERS),
            Self::LeSetScanEnable { .. } => (OGF_LE, OCF_LE_SET_SCAN_ENABLE),
            Self::LeCreateConnection { .. } => (OGF_LE, OCF_LE_CREATE_CONNECTION),
            Self::LeCreateConnectionCancel => (OGF_LE, OCF_LE_CREATE_CONNECTION_CANCEL),

            // Raw command
            Self::Raw { ogf, ocf, .. } => (*ogf, *ocf),
        }
    }

    /// Convert the command to its raw parameter bytes
    fn parameters(&self) -> Vec<u8> {
        match self {
            // Simple commands with no parameters
            Self::Inquiry
            | Self::InquiryCancel
            | Self::Reset
            | Self::LeReadBufferSize
            | Self::LeReadLocalSupportedFeatures
            | Self::LeReadAdvertisingPhysicalChannelTxPower
            | Self::LeCreateConnectionCancel => vec![],

            // Commands with simple parameters
            Self::SetEventMask { event_mask } => event_mask.to_le_bytes().to_vec(),
            Self::LeSetEventMask { event_mask } => event_mask.to_le_bytes().to_vec(),
            Self::LeSetRandomAddress { address } => address.to_vec(),
            Self::LeSetAdvertisingEnable { enable } => vec![*enable as u8],

            // Commands with complex parameters
            Self::CreateConnection {
                bd_addr,
                packet_type,
            } => {
                let mut params = Vec::with_capacity(8);
                params.extend_from_slice(bd_addr);
                params.extend_from_slice(&packet_type.to_le_bytes());
                params
            }

            Self::Disconnect { handle, reason } => {
                let mut params = Vec::with_capacity(3);
                params.extend_from_slice(&handle.to_le_bytes());
                params.push(*reason);
                params
            }

            Self::SniffMode {
                handle,
                max_interval,
                min_interval,
            } => {
                let mut params = Vec::with_capacity(5);
                params.extend_from_slice(&handle.to_le_bytes());
                params.extend_from_slice(&max_interval.to_le_bytes());
                params.extend_from_slice(&min_interval.to_le_bytes());
                params
            }

            Self::ExitSniffMode { handle } => handle.to_le_bytes().to_vec(),

            Self::LeSetAdvertisingParameters {
                min_interval,
                max_interval,
                advertising_type,
                own_address_type,
                peer_address_type,
                peer_address,
                channel_map,
                filter_policy,
            } => {
                let mut params = Vec::with_capacity(15);
                params.extend_from_slice(&min_interval.to_le_bytes());
                params.extend_from_slice(&max_interval.to_le_bytes());
                params.push(*advertising_type);
                params.push(*own_address_type);
                params.push(*peer_address_type);
                params.extend_from_slice(peer_address);
                params.push(*channel_map);
                params.push(*filter_policy);
                params
            }

            Self::LeSetAdvertisingData { data } => {
                if data.len() > HCI_MAX_PARAM_LEN {
                    panic!("Advertising data too long");
                }
                let mut params = Vec::with_capacity(data.len() + 1);
                params.push(data.len() as u8);
                params.extend_from_slice(data);
                params
            }

            Self::LeSetScanResponseData { data } => {
                if data.len() > HCI_MAX_PARAM_LEN {
                    panic!("Scan response data too long");
                }
                let mut params = Vec::with_capacity(data.len() + 1);
                params.push(data.len() as u8);
                params.extend_from_slice(data);
                params
            }

            Self::LeSetScanParameters {
                scan_type,
                scan_interval,
                scan_window,
                own_address_type,
                filter_policy,
            } => {
                let mut params = Vec::with_capacity(7);
                params.push(*scan_type);
                params.extend_from_slice(&scan_interval.to_le_bytes());
                params.extend_from_slice(&scan_window.to_le_bytes());
                params.push(*own_address_type);
                params.push(*filter_policy);
                params
            }

            Self::LeSetScanEnable {
                enable,
                filter_duplicates,
            } => {
                vec![*enable as u8, *filter_duplicates as u8]
            }

            Self::LeCreateConnection {
                peer_addr,
                peer_addr_type,
                own_address_type,
                conn_interval_min,
                conn_interval_max,
                conn_latency,
                supervision_timeout,
                min_ce_length,
                max_ce_length,
            } => {
                let mut params = Vec::with_capacity(24);
                params.extend_from_slice(peer_addr);
                params.push(*peer_addr_type);
                params.push(*own_address_type);
                params.extend_from_slice(&conn_interval_min.to_le_bytes());
                params.extend_from_slice(&conn_interval_max.to_le_bytes());
                params.extend_from_slice(&conn_latency.to_le_bytes());
                params.extend_from_slice(&supervision_timeout.to_le_bytes());
                params.extend_from_slice(&min_ce_length.to_le_bytes());
                params.extend_from_slice(&max_ce_length.to_le_bytes());
                params
            }

            Self::Raw { parameters, .. } => parameters.clone(),
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

    /// Get the event code
    pub fn get_event_code(&self) -> u8 {
        self.event_code
    }

    /// Get the parameters
    pub fn get_parameters(&self) -> &[u8] {
        &self.parameters
    }

    /// Check if this event is a command complete for the given opcode
    pub fn is_command_complete(&self, ogf: u8, ocf: u16) -> bool {
        if self.event_code != EVT_CMD_COMPLETE || self.parameters.len() < 3 {
            return false;
        }

        let opcode = u16::from_le_bytes([self.parameters[1], self.parameters[2]]);
        let command_ogf = (opcode >> 10) as u8;
        let command_ocf = opcode & 0x3FF;

        command_ogf == ogf && command_ocf == ocf
    }

    /// Get the status from a command complete event
    pub fn get_status(&self) -> u8 {
        if self.parameters.len() < 4 {
            return 0xFF; // Error code for invalid event
        }

        match self.event_code {
            EVT_CMD_COMPLETE => self.parameters[3],
            EVT_CMD_STATUS => self.parameters[0],
            _ => 0xFF, // Error code for invalid event
        }
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
    /// Parse one or more LE Advertising Reports from an HCI Meta Event
    pub fn parse_from_event(event: &HciEvent) -> Result<Vec<Self>, crate::error::Error> {
        if event.event_code != EVT_LE_META_EVENT || event.parameters.is_empty() {
            return Err(crate::error::Error::InvalidPacket(
                "Not an LE meta event".into(),
            ));
        }

        let subevent_code = event.parameters[0];
        if subevent_code != EVT_LE_ADVERTISING_REPORT {
            return Err(crate::error::Error::InvalidPacket(
                "Not an advertising report".into(),
            ));
        }

        let num_reports = event.parameters[1];
        if num_reports == 0 {
            return Ok(Vec::new());
        }

        let mut reports = Vec::with_capacity(num_reports as usize);
        let mut offset = 2; // Skip subevent code and num reports

        for _ in 0..num_reports {
            if offset + 10 >= event.parameters.len() {
                break;
            }

            let event_type = event.parameters[offset];
            offset += 1;

            let address_type = event.parameters[offset];
            offset += 1;

            let mut address = [0u8; 6];
            address.copy_from_slice(&event.parameters[offset..offset + 6]);
            offset += 6;

            if offset >= event.parameters.len() {
                break;
            }

            let data_length = event.parameters[offset];
            offset += 1;

            if offset + data_length as usize >= event.parameters.len() {
                break;
            }

            let data = event.parameters[offset..offset + data_length as usize].to_vec();
            offset += data_length as usize;

            if offset >= event.parameters.len() {
                break;
            }

            let rssi = event.parameters[offset] as i8;
            offset += 1;

            reports.push(LeAdvertisingReport {
                event_type,
                address_type,
                address,
                data_length,
                data,
                rssi,
            });
        }

        Ok(reports)
    }
}
