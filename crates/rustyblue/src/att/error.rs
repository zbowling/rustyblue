//! Error handling for the ATT protocol
use super::constants::*;
use crate::l2cap::L2capError;
use thiserror::Error;

/// ATT error codes as defined in the specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttErrorCode {
    /// No error
    NoError,
    /// Invalid handle
    InvalidHandle,
    /// Read not permitted
    ReadNotPermitted,
    /// Write not permitted
    WriteNotPermitted,
    /// Invalid PDU
    InvalidPdu,
    /// Insufficient authentication
    InsufficientAuthentication,
    /// Request not supported
    RequestNotSupported,
    /// Invalid offset
    InvalidOffset,
    /// Insufficient authorization
    InsufficientAuthorization,
    /// Prepare queue full
    PrepareQueueFull,
    /// Attribute not found
    AttributeNotFound,
    /// Attribute not long
    AttributeNotLong,
    /// Insufficient encryption key size
    InsufficientEncryptionKeySize,
    /// Invalid attribute value length
    InvalidAttributeValueLength,
    /// Unlikely error
    Unlikely,
    /// Insufficient encryption
    InsufficientEncryption,
    /// Unsupported group type
    UnsupportedGroupType,
    /// Insufficient resources
    InsufficientResources,
    /// Database out of sync
    DatabaseOutOfSync,
    /// Value not allowed
    ValueNotAllowed,
    /// Application error
    ApplicationError(u8),
    /// Common profile error
    CommonProfileError(u8),
    /// Unknown error code
    Unknown(u8),
}

impl From<u8> for AttErrorCode {
    fn from(code: u8) -> Self {
        match code {
            0 => AttErrorCode::NoError,
            ATT_ERROR_INVALID_HANDLE => AttErrorCode::InvalidHandle,
            ATT_ERROR_READ_NOT_PERMITTED => AttErrorCode::ReadNotPermitted,
            ATT_ERROR_WRITE_NOT_PERMITTED => AttErrorCode::WriteNotPermitted,
            ATT_ERROR_INVALID_PDU => AttErrorCode::InvalidPdu,
            ATT_ERROR_INSUFFICIENT_AUTHENTICATION => AttErrorCode::InsufficientAuthentication,
            ATT_ERROR_REQUEST_NOT_SUPPORTED => AttErrorCode::RequestNotSupported,
            ATT_ERROR_INVALID_OFFSET => AttErrorCode::InvalidOffset,
            ATT_ERROR_INSUFFICIENT_AUTHORIZATION => AttErrorCode::InsufficientAuthorization,
            ATT_ERROR_PREPARE_QUEUE_FULL => AttErrorCode::PrepareQueueFull,
            ATT_ERROR_ATTRIBUTE_NOT_FOUND => AttErrorCode::AttributeNotFound,
            ATT_ERROR_ATTRIBUTE_NOT_LONG => AttErrorCode::AttributeNotLong,
            ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE => {
                AttErrorCode::InsufficientEncryptionKeySize
            }
            ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LENGTH => AttErrorCode::InvalidAttributeValueLength,
            ATT_ERROR_UNLIKELY => AttErrorCode::Unlikely,
            ATT_ERROR_INSUFFICIENT_ENCRYPTION => AttErrorCode::InsufficientEncryption,
            ATT_ERROR_UNSUPPORTED_GROUP_TYPE => AttErrorCode::UnsupportedGroupType,
            ATT_ERROR_INSUFFICIENT_RESOURCES => AttErrorCode::InsufficientResources,
            ATT_ERROR_DATABASE_OUT_OF_SYNC => AttErrorCode::DatabaseOutOfSync,
            ATT_ERROR_VALUE_NOT_ALLOWED => AttErrorCode::ValueNotAllowed,
            c if c >= ATT_ERROR_APPLICATION_ERROR_START && c <= ATT_ERROR_APPLICATION_ERROR_END => {
                AttErrorCode::ApplicationError(c)
            }
            c if c >= ATT_ERROR_COMMON_PROFILE_ERROR_START
                && c <= ATT_ERROR_COMMON_PROFILE_ERROR_END =>
            {
                AttErrorCode::CommonProfileError(c)
            }
            _ => AttErrorCode::Unknown(code),
        }
    }
}

impl Into<u8> for AttErrorCode {
    fn into(self) -> u8 {
        match self {
            AttErrorCode::NoError => 0,
            AttErrorCode::InvalidHandle => ATT_ERROR_INVALID_HANDLE,
            AttErrorCode::ReadNotPermitted => ATT_ERROR_READ_NOT_PERMITTED,
            AttErrorCode::WriteNotPermitted => ATT_ERROR_WRITE_NOT_PERMITTED,
            AttErrorCode::InvalidPdu => ATT_ERROR_INVALID_PDU,
            AttErrorCode::InsufficientAuthentication => ATT_ERROR_INSUFFICIENT_AUTHENTICATION,
            AttErrorCode::RequestNotSupported => ATT_ERROR_REQUEST_NOT_SUPPORTED,
            AttErrorCode::InvalidOffset => ATT_ERROR_INVALID_OFFSET,
            AttErrorCode::InsufficientAuthorization => ATT_ERROR_INSUFFICIENT_AUTHORIZATION,
            AttErrorCode::PrepareQueueFull => ATT_ERROR_PREPARE_QUEUE_FULL,
            AttErrorCode::AttributeNotFound => ATT_ERROR_ATTRIBUTE_NOT_FOUND,
            AttErrorCode::AttributeNotLong => ATT_ERROR_ATTRIBUTE_NOT_LONG,
            AttErrorCode::InsufficientEncryptionKeySize => {
                ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE
            }
            AttErrorCode::InvalidAttributeValueLength => ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LENGTH,
            AttErrorCode::Unlikely => ATT_ERROR_UNLIKELY,
            AttErrorCode::InsufficientEncryption => ATT_ERROR_INSUFFICIENT_ENCRYPTION,
            AttErrorCode::UnsupportedGroupType => ATT_ERROR_UNSUPPORTED_GROUP_TYPE,
            AttErrorCode::InsufficientResources => ATT_ERROR_INSUFFICIENT_RESOURCES,
            AttErrorCode::DatabaseOutOfSync => ATT_ERROR_DATABASE_OUT_OF_SYNC,
            AttErrorCode::ValueNotAllowed => ATT_ERROR_VALUE_NOT_ALLOWED,
            AttErrorCode::ApplicationError(code) => code,
            AttErrorCode::CommonProfileError(code) => code,
            AttErrorCode::Unknown(code) => code,
        }
    }
}

/// ATT Error type
#[derive(Debug, Error)]
pub enum AttError {
    #[error("ATT error: {0:?} on handle {1}")]
    Protocol(AttErrorCode, u16),

    #[error("Attribute not found")]
    AttributeNotFound,

    #[error("Read not permitted")]
    ReadNotPermitted,

    #[error("Write not permitted")]
    WriteNotPermitted,

    #[error("Invalid handle: {0}")]
    InvalidHandle(u16),

    #[error("Invalid PDU")]
    InvalidPdu,

    #[error("Invalid offset: {0}")]
    InvalidOffset(u16),

    #[error("Invalid attribute value length")]
    InvalidAttributeValueLength,

    #[error("Insufficient authentication")]
    InsufficientAuthentication,

    #[error("Insufficient authorization")]
    InsufficientAuthorization,

    #[error("Insufficient encryption key size")]
    InsufficientEncryptionKeySize,

    #[error("Insufficient encryption")]
    InsufficientEncryption,

    #[error("Attribute not long")]
    AttributeNotLong,

    #[error("Prepare queue full")]
    PrepareQueueFull,

    #[error("Unlikely error")]
    Unlikely,

    #[error("Request not supported")]
    RequestNotSupported,

    #[error("Unsupported group type")]
    UnsupportedGroupType,

    #[error("Insufficient resources")]
    InsufficientResources,

    #[error("Database out of sync")]
    DatabaseOutOfSync,

    #[error("Value not allowed")]
    ValueNotAllowed,

    #[error("Application error: {0}")]
    ApplicationError(u8),

    #[error("L2CAP error: {0}")]
    L2capError(#[from] L2capError),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Invalid state for operation")]
    InvalidState,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<AttErrorCode> for AttError {
    fn from(code: AttErrorCode) -> Self {
        match code {
            AttErrorCode::NoError => AttError::Unknown("No error".into()),
            AttErrorCode::InvalidHandle => AttError::InvalidHandle(0),
            AttErrorCode::ReadNotPermitted => AttError::ReadNotPermitted,
            AttErrorCode::WriteNotPermitted => AttError::WriteNotPermitted,
            AttErrorCode::InvalidPdu => AttError::InvalidPdu,
            AttErrorCode::InsufficientAuthentication => AttError::InsufficientAuthentication,
            AttErrorCode::RequestNotSupported => AttError::RequestNotSupported,
            AttErrorCode::InvalidOffset => AttError::InvalidOffset(0),
            AttErrorCode::InsufficientAuthorization => AttError::InsufficientAuthorization,
            AttErrorCode::PrepareQueueFull => AttError::PrepareQueueFull,
            AttErrorCode::AttributeNotFound => AttError::AttributeNotFound,
            AttErrorCode::AttributeNotLong => AttError::AttributeNotLong,
            AttErrorCode::InsufficientEncryptionKeySize => AttError::InsufficientEncryptionKeySize,
            AttErrorCode::InvalidAttributeValueLength => AttError::InvalidAttributeValueLength,
            AttErrorCode::Unlikely => AttError::Unlikely,
            AttErrorCode::InsufficientEncryption => AttError::InsufficientEncryption,
            AttErrorCode::UnsupportedGroupType => AttError::UnsupportedGroupType,
            AttErrorCode::InsufficientResources => AttError::InsufficientResources,
            AttErrorCode::DatabaseOutOfSync => AttError::DatabaseOutOfSync,
            AttErrorCode::ValueNotAllowed => AttError::ValueNotAllowed,
            AttErrorCode::ApplicationError(code) => AttError::ApplicationError(code),
            AttErrorCode::CommonProfileError(code) => AttError::ApplicationError(code),
            AttErrorCode::Unknown(code) => {
                AttError::Unknown(format!("Unknown error code: {}", code))
            }
        }
    }
}

impl AttError {
    /// Convert to ATT error code
    pub fn to_error_code(&self) -> AttErrorCode {
        match self {
            AttError::Protocol(code, _) => *code,
            AttError::AttributeNotFound => AttErrorCode::AttributeNotFound,
            AttError::ReadNotPermitted => AttErrorCode::ReadNotPermitted,
            AttError::WriteNotPermitted => AttErrorCode::WriteNotPermitted,
            AttError::InvalidHandle(_) => AttErrorCode::InvalidHandle,
            AttError::InvalidPdu => AttErrorCode::InvalidPdu,
            AttError::InvalidOffset(_) => AttErrorCode::InvalidOffset,
            AttError::InvalidAttributeValueLength => AttErrorCode::InvalidAttributeValueLength,
            AttError::InsufficientAuthentication => AttErrorCode::InsufficientAuthentication,
            AttError::InsufficientAuthorization => AttErrorCode::InsufficientAuthorization,
            AttError::InsufficientEncryptionKeySize => AttErrorCode::InsufficientEncryptionKeySize,
            AttError::InsufficientEncryption => AttErrorCode::InsufficientEncryption,
            AttError::AttributeNotLong => AttErrorCode::AttributeNotLong,
            AttError::PrepareQueueFull => AttErrorCode::PrepareQueueFull,
            AttError::Unlikely => AttErrorCode::Unlikely,
            AttError::RequestNotSupported => AttErrorCode::RequestNotSupported,
            AttError::UnsupportedGroupType => AttErrorCode::UnsupportedGroupType,
            AttError::InsufficientResources => AttErrorCode::InsufficientResources,
            AttError::DatabaseOutOfSync => AttErrorCode::DatabaseOutOfSync,
            AttError::ValueNotAllowed => AttErrorCode::ValueNotAllowed,
            AttError::ApplicationError(code) => AttErrorCode::ApplicationError(*code),
            AttError::L2capError(_) => AttErrorCode::Unlikely,
            AttError::InvalidParameter(_) => AttErrorCode::InvalidPdu,
            AttError::InvalidState => AttErrorCode::RequestNotSupported,
            AttError::Unknown(_) => AttErrorCode::Unlikely,
        }
    }

    /// Get the handle associated with this error, if any
    pub fn handle(&self) -> Option<u16> {
        match self {
            AttError::Protocol(_, handle) => Some(*handle),
            AttError::InvalidHandle(handle) => Some(*handle),
            AttError::InvalidOffset(handle) => Some(*handle),
            _ => None,
        }
    }
}

/// ATT Result type
pub type AttResult<T> = Result<T, AttError>;
