// Address types
pub const PUBLIC_DEVICE_ADDRESS: u8 = 0x00;
pub const RANDOM_DEVICE_ADDRESS: u8 = 0x01;
pub const PUBLIC_IDENTITY_ADDRESS: u8 = 0x02;
pub const RANDOM_IDENTITY_ADDRESS: u8 = 0x03;

// HCI Constants
pub const OGF_LINK_CTL: u8 = 0x01;
pub const OGF_HOST_CTL: u8 = 0x03;
pub const OGF_INFO_PARAM: u8 = 0x04;
pub const OGF_LE_CTL: u8 = 0x08;

pub const OCF_READ_LOCAL_NAME: u16 = 0x0014;
pub const OCF_WRITE_LOCAL_NAME: u16 = 0x0013;
pub const OCF_READ_BD_ADDR: u16 = 0x0009;
pub const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000B;
pub const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000C;
pub const OCF_LE_CREATE_CONNECTION: u16 = 0x000D;
pub const OCF_LE_SET_CONNECTION_PARAMETERS: u16 = 0x0013;
pub const OCF_DISCONNECT: u16 = 0x0006;

pub const EVT_LE_META_EVENT: u8 = 0x3E;
pub const EVT_LE_ADVERTISING_REPORT: u8 = 0x02;
pub const EVT_LE_CONNECTION_COMPLETE: u8 = 0x01;
pub const EVT_LE_DISCONNECTION_COMPLETE: u8 = 0x05;

// LE Scan parameters
pub const LE_SCAN_ACTIVE: u8 = 0x01;
pub const LE_SCAN_INTERVAL: u16 = 0x0010; // 10 ms
pub const LE_SCAN_WINDOW: u16 = 0x0010; // 10 ms

// LE Connection parameters
pub const LE_CONN_INTERVAL_MIN: u16 = 0x0006; // 7.5 ms
pub const LE_CONN_INTERVAL_MAX: u16 = 0x0008; // 10 ms
pub const LE_CONN_LATENCY: u16 = 0x0000; // 0
pub const LE_SUPERVISION_TIMEOUT: u16 = 0x0048; // 720 ms
pub const LE_MIN_CE_LENGTH: u16 = 0x0000; // 0 ms
pub const LE_MAX_CE_LENGTH: u16 = 0x0000; // 0 ms

// Advertising Data Types
pub const ADV_TYPE_FLAGS: u8 = 0x01;
pub const ADV_TYPE_16BIT_SERVICE_UUID_PARTIAL: u8 = 0x02;
pub const ADV_TYPE_16BIT_SERVICE_UUID_COMPLETE: u8 = 0x03;
pub const ADV_TYPE_32BIT_SERVICE_UUID_PARTIAL: u8 = 0x04;
pub const ADV_TYPE_32BIT_SERVICE_UUID_COMPLETE: u8 = 0x05;
pub const ADV_TYPE_128BIT_SERVICE_UUID_PARTIAL: u8 = 0x06;
pub const ADV_TYPE_128BIT_SERVICE_UUID_COMPLETE: u8 = 0x07;
pub const ADV_TYPE_SHORT_LOCAL_NAME: u8 = 0x08;
pub const ADV_TYPE_COMPLETE_LOCAL_NAME: u8 = 0x09;
pub const ADV_TYPE_TX_POWER_LEVEL: u8 = 0x0A;
pub const ADV_TYPE_CLASS_OF_DEVICE: u8 = 0x0D;
pub const ADV_TYPE_SIMPLE_PAIRING_HASH: u8 = 0x0E;
pub const ADV_TYPE_SIMPLE_PAIRING_RANDOMIZER: u8 = 0x0F;
pub const ADV_TYPE_DEVICE_ID: u8 = 0x10;
pub const ADV_TYPE_APPEARANCE: u8 = 0x19;
pub const ADV_TYPE_MANUFACTURER_SPECIFIC: u8 = 0xFF;
