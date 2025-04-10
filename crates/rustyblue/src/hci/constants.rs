//! HCI protocol constants
//!
//! This module contains constants used in the Bluetooth HCI protocol.

// HCI packet types
pub const HCI_COMMAND_PKT: u8 = 0x01;
pub const HCI_ACL_PKT: u8 = 0x02;
pub const HCI_SCO_PKT: u8 = 0x03;
pub const HCI_EVENT_PKT: u8 = 0x04;
pub const HCI_ISO_PKT: u8 = 0x05;

// Maximum size of HCI command parameters
pub const HCI_MAX_PARAM_LEN: usize = 255;

// Common OGF (Opcode Group Field) values
pub const OGF_LINK_CTL: u8 = 0x01;
pub const OGF_LINK_POLICY: u8 = 0x02;
pub const OGF_HOST_CTL: u8 = 0x03;
pub const OGF_INFO_PARAM: u8 = 0x04;
pub const OGF_STATUS_PARAM: u8 = 0x05;
pub const OGF_LE: u8 = 0x08;

// Link Control Commands (OGF: 0x01)
pub const OCF_INQUIRY: u16 = 0x0001;
pub const OCF_INQUIRY_CANCEL: u16 = 0x0002;
pub const OCF_CREATE_CONNECTION: u16 = 0x0005;
pub const OCF_DISCONNECT: u16 = 0x0006;

// Link Policy Commands (OGF: 0x02)
pub const OCF_SNIFF_MODE: u16 = 0x0003;
pub const OCF_EXIT_SNIFF_MODE: u16 = 0x0004;

// Host Controller Commands (OGF: 0x03)
pub const OCF_RESET: u16 = 0x0003;
pub const OCF_SET_EVENT_MASK: u16 = 0x0001;

// LE Command OCF values (OGF: 0x08)
pub const OCF_LE_SET_EVENT_MASK: u16 = 0x0001;
pub const OCF_LE_READ_BUFFER_SIZE: u16 = 0x0002;
pub const OCF_LE_READ_LOCAL_SUPPORTED_FEATURES: u16 = 0x0003;
pub const OCF_LE_SET_RANDOM_ADDRESS: u16 = 0x0005;
pub const OCF_LE_SET_ADVERTISING_PARAMETERS: u16 = 0x0006;
pub const OCF_LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER: u16 = 0x0007;
pub const OCF_LE_SET_ADVERTISING_DATA: u16 = 0x0008;
pub const OCF_LE_SET_SCAN_RESPONSE_DATA: u16 = 0x0009;
pub const OCF_LE_SET_ADVERTISING_ENABLE: u16 = 0x000A;
pub const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000B;
pub const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;
pub const OCF_LE_CREATE_CONNECTION: u16 = 0x000D;
pub const OCF_LE_CREATE_CONNECTION_CANCEL: u16 = 0x000E;

// HCI Events
pub const EVT_DISCONN_COMPLETE: u8 = 0x05;
pub const EVT_ENCRYPTION_CHANGE: u8 = 0x08;
pub const EVT_CMD_COMPLETE: u8 = 0x0E;
pub const EVT_CMD_STATUS: u8 = 0x0F;
pub const EVT_LE_META_EVENT: u8 = 0x3E;

// LE Meta Events
pub const EVT_LE_CONN_COMPLETE: u8 = 0x01;
pub const EVT_LE_ADVERTISING_REPORT: u8 = 0x02;
pub const EVT_LE_CONN_UPDATE_COMPLETE: u8 = 0x03;
