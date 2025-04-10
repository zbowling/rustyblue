//! ATT Protocol constants

// ATT opcode values
pub const ATT_ERROR_RSP: u8 = 0x01;
pub const ATT_EXCHANGE_MTU_REQ: u8 = 0x02;
pub const ATT_EXCHANGE_MTU_RSP: u8 = 0x03;
pub const ATT_FIND_INFO_REQ: u8 = 0x04;
pub const ATT_FIND_INFO_RSP: u8 = 0x05;
pub const ATT_FIND_BY_TYPE_VALUE_REQ: u8 = 0x06;
pub const ATT_FIND_BY_TYPE_VALUE_RSP: u8 = 0x07;
pub const ATT_READ_BY_TYPE_REQ: u8 = 0x08;
pub const ATT_READ_BY_TYPE_RSP: u8 = 0x09;
pub const ATT_READ_REQ: u8 = 0x0A;
pub const ATT_READ_RSP: u8 = 0x0B;
pub const ATT_READ_BLOB_REQ: u8 = 0x0C;
pub const ATT_READ_BLOB_RSP: u8 = 0x0D;
pub const ATT_READ_MULTIPLE_REQ: u8 = 0x0E;
pub const ATT_READ_MULTIPLE_RSP: u8 = 0x0F;
pub const ATT_READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
pub const ATT_READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
pub const ATT_WRITE_REQ: u8 = 0x12;
pub const ATT_WRITE_RSP: u8 = 0x13;
pub const ATT_WRITE_CMD: u8 = 0x52;
pub const ATT_SIGNED_WRITE_CMD: u8 = 0xD2;
pub const ATT_PREPARE_WRITE_REQ: u8 = 0x16;
pub const ATT_PREPARE_WRITE_RSP: u8 = 0x17;
pub const ATT_EXECUTE_WRITE_REQ: u8 = 0x18;
pub const ATT_EXECUTE_WRITE_RSP: u8 = 0x19;
pub const ATT_HANDLE_VALUE_NTF: u8 = 0x1B;
pub const ATT_HANDLE_VALUE_IND: u8 = 0x1D;
pub const ATT_HANDLE_VALUE_CONF: u8 = 0x1E;
pub const ATT_MULTIPLE_HANDLE_VALUE_NTF: u8 = 0x23;

// ATT error codes
pub const ATT_ERROR_INVALID_HANDLE: u8 = 0x01;
pub const ATT_ERROR_READ_NOT_PERMITTED: u8 = 0x02;
pub const ATT_ERROR_WRITE_NOT_PERMITTED: u8 = 0x03;
pub const ATT_ERROR_INVALID_PDU: u8 = 0x04;
pub const ATT_ERROR_INSUFFICIENT_AUTHENTICATION: u8 = 0x05;
pub const ATT_ERROR_REQUEST_NOT_SUPPORTED: u8 = 0x06;
pub const ATT_ERROR_INVALID_OFFSET: u8 = 0x07;
pub const ATT_ERROR_INSUFFICIENT_AUTHORIZATION: u8 = 0x08;
pub const ATT_ERROR_PREPARE_QUEUE_FULL: u8 = 0x09;
pub const ATT_ERROR_ATTRIBUTE_NOT_FOUND: u8 = 0x0A;
pub const ATT_ERROR_ATTRIBUTE_NOT_LONG: u8 = 0x0B;
pub const ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE: u8 = 0x0C;
pub const ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LENGTH: u8 = 0x0D;
pub const ATT_ERROR_UNLIKELY: u8 = 0x0E;
pub const ATT_ERROR_INSUFFICIENT_ENCRYPTION: u8 = 0x0F;
pub const ATT_ERROR_UNSUPPORTED_GROUP_TYPE: u8 = 0x10;
pub const ATT_ERROR_INSUFFICIENT_RESOURCES: u8 = 0x11;
pub const ATT_ERROR_DATABASE_OUT_OF_SYNC: u8 = 0x12;
pub const ATT_ERROR_VALUE_NOT_ALLOWED: u8 = 0x13;
pub const ATT_ERROR_APPLICATION_ERROR_START: u8 = 0x80;
pub const ATT_ERROR_APPLICATION_ERROR_END: u8 = 0x9F;
pub const ATT_ERROR_COMMON_PROFILE_ERROR_START: u8 = 0xE0;
pub const ATT_ERROR_COMMON_PROFILE_ERROR_END: u8 = 0xFF;

// ATT attribute permission flags
pub const ATT_PERM_NONE: u16 = 0x0000;
pub const ATT_PERM_READ: u16 = 0x0001;
pub const ATT_PERM_WRITE: u16 = 0x0002;
pub const ATT_PERM_READ_ENCRYPTED: u16 = 0x0004;
pub const ATT_PERM_WRITE_ENCRYPTED: u16 = 0x0008;
pub const ATT_PERM_READ_AUTHENTICATED: u16 = 0x0010;
pub const ATT_PERM_WRITE_AUTHENTICATED: u16 = 0x0020;
pub const ATT_PERM_READ_AUTHORIZED: u16 = 0x0040;
pub const ATT_PERM_WRITE_AUTHORIZED: u16 = 0x0080;
pub const ATT_PERM_READ_ENCRYPTED_MITM: u16 = ATT_PERM_READ_ENCRYPTED | ATT_PERM_READ_AUTHENTICATED;
pub const ATT_PERM_WRITE_ENCRYPTED_MITM: u16 = ATT_PERM_WRITE_ENCRYPTED | ATT_PERM_WRITE_AUTHENTICATED;

// ATT handle values
pub const ATT_HANDLE_MIN: u16 = 0x0001;
pub const ATT_HANDLE_MAX: u16 = 0xFFFF;

// ATT attribute value length limits
pub const ATT_DEFAULT_MTU: u16 = 23;
pub const ATT_MAX_MTU: u16 = 517;

// ATT value length limits based on MTU
pub const ATT_MTU_HEADER_SIZE: usize = 3; // Opcode (1) + handle (2)

// ATT Find Information Response Format
pub const ATT_FIND_INFO_RSP_FORMAT_16BIT: u8 = 0x01;
pub const ATT_FIND_INFO_RSP_FORMAT_128BIT: u8 = 0x02;

// ATT write request flags
pub const ATT_EXEC_WRITE_CANCEL: u8 = 0x00;
pub const ATT_EXEC_WRITE_COMMIT: u8 = 0x01;

// ATT prepare write queue size
pub const ATT_PREPARE_WRITE_QUEUE_SIZE: usize = 64;

// ATT L2CAP channel ID
pub const ATT_CID: u16 = 0x0004;

// Special UUID values used in ATT
pub const PRIMARY_SERVICE_UUID: u16 = 0x2800;
pub const SECONDARY_SERVICE_UUID: u16 = 0x2801;
pub const INCLUDE_UUID: u16 = 0x2802;
pub const CHARACTERISTIC_UUID: u16 = 0x2803;
pub const CHAR_EXTENDED_PROPS_UUID: u16 = 0x2900;
pub const CHAR_USER_DESC_UUID: u16 = 0x2901;
pub const CLIENT_CHAR_CONFIG_UUID: u16 = 0x2902;
pub const SERVER_CHAR_CONFIG_UUID: u16 = 0x2903;
pub const CHAR_FORMAT_UUID: u16 = 0x2904;
pub const CHAR_AGGREGATE_FORMAT_UUID: u16 = 0x2905;

// GATT service range
pub const GATT_SERVICE_START: u16 = 0x1800;
pub const GATT_SERVICE_END: u16 = 0x18FF;