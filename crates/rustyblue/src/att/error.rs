//! Error handling for the ATT protocol
use std::fmt;

/// ATT Protocol Error Codes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttError {
    InvalidHandle,
    ReadNotPermitted,
    WriteNotPermitted,
    InvalidPdu,
    InsufficientAuthentication,
    RequestNotSupported,
    InvalidOffset,
    InsufficientAuthorization,
    PrepareQueueFull,
    AttributeNotFound,
    AttributeNotLong,
    InsufficientEncryptionKeySize,
    InvalidAttributeValueLength,
    UnlikelyError,
    InsufficientEncryption,
    UnsupportedGroupType,
    InsufficientResources,
    DatabaseOutOfSync,
    ValueNotAllowed,
    // Additional variants needed throughout the codebase
    InvalidState,
    InvalidParameter(String),
    Unknown(String),
    Protocol(u8, u16), // error_code, handle
    UnsupportedOpcode(u8),
    InvalidOpcode(u8),
    UnknownResponse(String),
    UnexpectedResponse,
}

/// ATT Error Codes as defined in the Bluetooth specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttErrorCode {
    InvalidHandle = 0x01,
    ReadNotPermitted = 0x02,
    WriteNotPermitted = 0x03,
    InvalidPdu = 0x04,
    InsufficientAuthentication = 0x05,
    RequestNotSupported = 0x06,
    InvalidOffset = 0x07,
    InsufficientAuthorization = 0x08,
    PrepareQueueFull = 0x09,
    AttributeNotFound = 0x0A,
    AttributeNotLong = 0x0B,
    InsufficientEncryptionKeySize = 0x0C,
    InvalidAttributeValueLength = 0x0D,
    UnlikelyError = 0x0E,
    InsufficientEncryption = 0x0F,
    UnsupportedGroupType = 0x10,
    InsufficientResources = 0x11,
    DatabaseOutOfSync = 0x12,
    ValueNotAllowed = 0x13,
}

impl From<AttErrorCode> for u8 {
    fn from(code: AttErrorCode) -> Self {
        code as u8
    }
}

impl From<u8> for AttErrorCode {
    fn from(value: u8) -> Self {
        match value {
            0x01 => AttErrorCode::InvalidHandle,
            0x02 => AttErrorCode::ReadNotPermitted,
            0x03 => AttErrorCode::WriteNotPermitted,
            0x04 => AttErrorCode::InvalidPdu,
            0x05 => AttErrorCode::InsufficientAuthentication,
            0x06 => AttErrorCode::RequestNotSupported,
            0x07 => AttErrorCode::InvalidOffset,
            0x08 => AttErrorCode::InsufficientAuthorization,
            0x09 => AttErrorCode::PrepareQueueFull,
            0x0A => AttErrorCode::AttributeNotFound,
            0x0B => AttErrorCode::AttributeNotLong,
            0x0C => AttErrorCode::InsufficientEncryptionKeySize,
            0x0D => AttErrorCode::InvalidAttributeValueLength,
            0x0E => AttErrorCode::UnlikelyError,
            0x0F => AttErrorCode::InsufficientEncryption,
            0x10 => AttErrorCode::UnsupportedGroupType,
            0x11 => AttErrorCode::InsufficientResources,
            0x12 => AttErrorCode::DatabaseOutOfSync,
            0x13 => AttErrorCode::ValueNotAllowed,
            _ => AttErrorCode::UnlikelyError,
        }
    }
}

impl fmt::Display for AttError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttError::InvalidHandle => write!(f, "Invalid handle"),
            AttError::ReadNotPermitted => write!(f, "Read not permitted"),
            AttError::WriteNotPermitted => write!(f, "Write not permitted"),
            AttError::InvalidPdu => write!(f, "Invalid PDU"),
            AttError::InsufficientAuthentication => write!(f, "Insufficient authentication"),
            AttError::RequestNotSupported => write!(f, "Request not supported"),
            AttError::InvalidOffset => write!(f, "Invalid offset"),
            AttError::InsufficientAuthorization => write!(f, "Insufficient authorization"),
            AttError::PrepareQueueFull => write!(f, "Prepare queue full"),
            AttError::AttributeNotFound => write!(f, "Attribute not found"),
            AttError::AttributeNotLong => write!(f, "Attribute not long"),
            AttError::InsufficientEncryptionKeySize => {
                write!(f, "Insufficient encryption key size")
            }
            AttError::InvalidAttributeValueLength => write!(f, "Invalid attribute value length"),
            AttError::UnlikelyError => write!(f, "Unlikely error"),
            AttError::InsufficientEncryption => write!(f, "Insufficient encryption"),
            AttError::UnsupportedGroupType => write!(f, "Unsupported group type"),
            AttError::InsufficientResources => write!(f, "Insufficient resources"),
            AttError::DatabaseOutOfSync => write!(f, "Database out of sync"),
            AttError::ValueNotAllowed => write!(f, "Value not allowed"),
            AttError::InvalidState => write!(f, "Invalid state for operation"),
            AttError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            AttError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
            AttError::Protocol(code, handle) => {
                write!(f, "ATT protocol error: {} on handle {}", code, handle)
            }
            AttError::UnsupportedOpcode(opcode) => write!(f, "Unsupported opcode: {}", opcode),
            AttError::InvalidOpcode(opcode) => write!(f, "Invalid opcode: {}", opcode),
            AttError::UnknownResponse(msg) => write!(f, "Unknown response: {}", msg),
            AttError::UnexpectedResponse => write!(f, "Unexpected response"),
        }
    }
}

impl std::error::Error for AttError {}

impl TryFrom<u8> for AttError {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AttError::InvalidHandle),
            0x02 => Ok(AttError::ReadNotPermitted),
            0x03 => Ok(AttError::WriteNotPermitted),
            0x04 => Ok(AttError::InvalidPdu),
            0x05 => Ok(AttError::InsufficientAuthentication),
            0x06 => Ok(AttError::RequestNotSupported),
            0x07 => Ok(AttError::InvalidOffset),
            0x08 => Ok(AttError::InsufficientAuthorization),
            0x09 => Ok(AttError::PrepareQueueFull),
            0x0A => Ok(AttError::AttributeNotFound),
            0x0B => Ok(AttError::AttributeNotLong),
            0x0C => Ok(AttError::InsufficientEncryptionKeySize),
            0x0D => Ok(AttError::InvalidAttributeValueLength),
            0x0E => Ok(AttError::UnlikelyError),
            0x0F => Ok(AttError::InsufficientEncryption),
            0x10 => Ok(AttError::UnsupportedGroupType),
            0x11 => Ok(AttError::InsufficientResources),
            0x12 => Ok(AttError::DatabaseOutOfSync),
            0x13 => Ok(AttError::ValueNotAllowed),
            _ => Err(()),
        }
    }
}

impl From<AttError> for u8 {
    fn from(error: AttError) -> Self {
        match error {
            AttError::InvalidHandle => 0x01,
            AttError::ReadNotPermitted => 0x02,
            AttError::WriteNotPermitted => 0x03,
            AttError::InvalidPdu => 0x04,
            AttError::InsufficientAuthentication => 0x05,
            AttError::RequestNotSupported => 0x06,
            AttError::InvalidOffset => 0x07,
            AttError::InsufficientAuthorization => 0x08,
            AttError::PrepareQueueFull => 0x09,
            AttError::AttributeNotFound => 0x0A,
            AttError::AttributeNotLong => 0x0B,
            AttError::InsufficientEncryptionKeySize => 0x0C,
            AttError::InvalidAttributeValueLength => 0x0D,
            AttError::UnlikelyError => 0x0E,
            AttError::InsufficientEncryption => 0x0F,
            AttError::UnsupportedGroupType => 0x10,
            AttError::InsufficientResources => 0x11,
            AttError::DatabaseOutOfSync => 0x12,
            AttError::ValueNotAllowed => 0x13,
            // For extended error types, return a general error
            _ => 0x0E, // Unlikely error
        }
    }
}

impl AttError {
    /// Get the handle associated with this error, if any
    pub fn handle(&self) -> Option<u16> {
        match self {
            AttError::Protocol(_, handle) => Some(*handle),
            _ => None,
        }
    }

    /// Convert to ATT error code
    pub fn to_att_code(&self) -> u8 {
        match self {
            AttError::InvalidHandle => 0x01,
            AttError::ReadNotPermitted => 0x02,
            AttError::WriteNotPermitted => 0x03,
            AttError::InvalidPdu => 0x04,
            AttError::InsufficientAuthentication => 0x05,
            AttError::RequestNotSupported => 0x06,
            AttError::InvalidOffset => 0x07,
            AttError::InsufficientAuthorization => 0x08,
            AttError::PrepareQueueFull => 0x09,
            AttError::AttributeNotFound => 0x0A,
            AttError::AttributeNotLong => 0x0B,
            AttError::InsufficientEncryptionKeySize => 0x0C,
            AttError::InvalidAttributeValueLength => 0x0D,
            AttError::UnlikelyError => 0x0E,
            AttError::InsufficientEncryption => 0x0F,
            AttError::UnsupportedGroupType => 0x10,
            AttError::InsufficientResources => 0x11,
            AttError::DatabaseOutOfSync => 0x12,
            AttError::ValueNotAllowed => 0x13,
            // For extended error types, return a general error
            _ => 0x0E, // Unlikely error
        }
    }
}

/// ATT Result type
pub type AttResult<T> = Result<T, AttError>;
