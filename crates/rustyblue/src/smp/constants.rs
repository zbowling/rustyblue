//! Constants for the Security Manager Protocol

// SMP command codes
pub const SMP_PAIRING_REQUEST: u8 = 0x01;
pub const SMP_PAIRING_RESPONSE: u8 = 0x02;
pub const SMP_PAIRING_CONFIRM: u8 = 0x03;
pub const SMP_PAIRING_RANDOM: u8 = 0x04;
pub const SMP_PAIRING_FAILED: u8 = 0x05;
pub const SMP_ENCRYPTION_INFORMATION: u8 = 0x06;
pub const SMP_MASTER_IDENTIFICATION: u8 = 0x07;
pub const SMP_IDENTITY_INFORMATION: u8 = 0x08;
pub const SMP_IDENTITY_ADDRESS_INFORMATION: u8 = 0x09;
pub const SMP_SIGNING_INFORMATION: u8 = 0x0A;
pub const SMP_SECURITY_REQUEST: u8 = 0x0B;
pub const SMP_PAIRING_PUBLIC_KEY: u8 = 0x0C;
pub const SMP_PAIRING_DHK_CHECK: u8 = 0x0D;
pub const SMP_PAIRING_KEYPRESS_NOTIFICATION: u8 = 0x0E;

// SMP fixed channel ID
pub const SMP_CID: u16 = 0x0006;

// IO Capability values
pub const SMP_IO_CAPABILITY_DISPLAY_ONLY: u8 = 0x00;
pub const SMP_IO_CAPABILITY_DISPLAY_YES_NO: u8 = 0x01;
pub const SMP_IO_CAPABILITY_KEYBOARD_ONLY: u8 = 0x02;
pub const SMP_IO_CAPABILITY_NO_INPUT_NO_OUTPUT: u8 = 0x03;
pub const SMP_IO_CAPABILITY_KEYBOARD_DISPLAY: u8 = 0x04;

// Authentication Requirements bit masks
pub const SMP_AUTH_REQ_BONDING: u8 = 0x01;
pub const SMP_AUTH_REQ_MITM: u8 = 0x04;
pub const SMP_AUTH_REQ_SC: u8 = 0x08;
pub const SMP_AUTH_REQ_KEYPRESS: u8 = 0x10;
pub const SMP_AUTH_REQ_CT2: u8 = 0x20;
pub const SMP_AUTH_REQ_RFU: u8 = 0xC0;

// Pairing Failed reason codes
pub const SMP_REASON_PASSKEY_ENTRY_FAILED: u8 = 0x01;
pub const SMP_REASON_OOB_NOT_AVAILABLE: u8 = 0x02;
pub const SMP_REASON_AUTHENTICATION_REQUIREMENTS: u8 = 0x03;
pub const SMP_REASON_CONFIRM_VALUE_FAILED: u8 = 0x04;
pub const SMP_REASON_PAIRING_NOT_SUPPORTED: u8 = 0x05;
pub const SMP_REASON_ENCRYPTION_KEY_SIZE: u8 = 0x06;
pub const SMP_REASON_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const SMP_REASON_UNSPECIFIED_REASON: u8 = 0x08;
pub const SMP_REASON_REPEATED_ATTEMPTS: u8 = 0x09;
pub const SMP_REASON_INVALID_PARAMETERS: u8 = 0x0A;
pub const SMP_REASON_DHKEY_CHECK_FAILED: u8 = 0x0B;
pub const SMP_REASON_NUMERIC_COMPARISON_FAILED: u8 = 0x0C;
pub const SMP_REASON_BR_EDR_PAIRING_IN_PROGRESS: u8 = 0x0D;
pub const SMP_REASON_CROSS_TRANSPORT_KEY_NOT_ALLOWED: u8 = 0x0E;

// SMP key distribution bit masks
pub const SMP_KEY_DIST_ENC_KEY: u8 = 0x01;
pub const SMP_KEY_DIST_ID_KEY: u8 = 0x02;
pub const SMP_KEY_DIST_SIGN_KEY: u8 = 0x04;
pub const SMP_KEY_DIST_LINK_KEY: u8 = 0x08;

// SMP encryption key size limits
pub const SMP_MIN_ENCRYPTION_KEY_SIZE: u8 = 7;
pub const SMP_MAX_ENCRYPTION_KEY_SIZE: u8 = 16;

// SMP pairing methods
pub const SMP_PAIRING_METHOD_JUST_WORKS: u8 = 0x00;
pub const SMP_PAIRING_METHOD_PASSKEY_ENTRY: u8 = 0x01;
pub const SMP_PAIRING_METHOD_NUMERIC_COMPARISON: u8 = 0x02;
pub const SMP_PAIRING_METHOD_OOB: u8 = 0x03;

// Keypress notification types
pub const SMP_KEYPRESS_ENTRY_STARTED: u8 = 0x00;
pub const SMP_KEYPRESS_DIGIT_ENTERED: u8 = 0x01;
pub const SMP_KEYPRESS_DIGIT_ERASED: u8 = 0x02;
pub const SMP_KEYPRESS_CLEARED: u8 = 0x03;
pub const SMP_KEYPRESS_ENTRY_COMPLETED: u8 = 0x04;

// Transport types for secure connections
pub const SMP_TRANSPORT_LE: u8 = 0x00;
pub const SMP_TRANSPORT_BR_EDR: u8 = 0x01;

// SMP timeout values (in milliseconds)
pub const SMP_TIMEOUT_GENERAL: u64 = 30000; // 30 seconds general timeout
pub const SMP_TIMEOUT_PASSKEY: u64 = 60000; // 60 seconds for passkey entry
pub const SMP_TIMEOUT_NUMERIC_COMPARISON: u64 = 30000; // 30 seconds for numeric comparison
pub const SMP_TIMEOUT_USER_AUTHORIZATION: u64 = 60000; // 60 seconds for user authorization

// SMP address types
pub const SMP_ADDR_TYPE_PUBLIC: u8 = 0x00;
pub const SMP_ADDR_TYPE_RANDOM: u8 = 0x01;
