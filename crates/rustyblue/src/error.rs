//! Error types for the rustyblue library
//!
//! This module defines the error types used throughout the library.

use std::fmt;

/// Errors that can occur when working with HCI sockets
#[derive(Debug)]
pub enum HciError {
    SocketError(String),
    BindError(String),
    SendError(String),
    ReceiveError(String),
    InvalidParamLength(usize),
    InvalidPacketFormat(String),
    Unsupported,
}

impl fmt::Display for HciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HciError::SocketError(msg) => write!(f, "Failed to open HCI socket: {}", msg),
            HciError::BindError(msg) => write!(f, "Failed to bind to HCI device: {}", msg),
            HciError::SendError(msg) => write!(f, "Failed to send HCI command: {}", msg),
            HciError::ReceiveError(msg) => write!(f, "Failed to receive HCI event: {}", msg),
            HciError::InvalidParamLength(len) => write!(f, "Invalid parameter length: {}", len),
            HciError::InvalidPacketFormat(msg) => write!(f, "Invalid HCI packet format: {}", msg),
            HciError::Unsupported => write!(f, "Unsupported operation"),
        }
    }
}

impl std::error::Error for HciError {}

/// General errors that can occur in the library
#[derive(Debug)]
pub enum Error {
    Hci(HciError),
    Io(std::io::Error),
    NotConnected,
    NotImplemented(String),
    InvalidPacket(String),
    ServiceDiscoveryFailed(String),
    ProtocolError(String),
    Timeout,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Hci(err) => write!(f, "HCI error: {}", err),
            Error::Io(err) => write!(f, "I/O error: {}", err),
            Error::NotConnected => write!(f, "Not connected"),
            Error::NotImplemented(msg) => write!(f, "Feature not implemented: {}", msg),
            Error::InvalidPacket(msg) => write!(f, "Invalid packet: {}", msg),
            Error::ServiceDiscoveryFailed(msg) => write!(f, "Service discovery failed: {}", msg),
            Error::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            Error::Timeout => write!(f, "Operation timeout"),
        }
    }
}

impl std::error::Error for Error {}

impl From<HciError> for Error {
    fn from(err: HciError) -> Self {
        Error::Hci(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}
