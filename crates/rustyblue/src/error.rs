//! Error types for the rustyblue library
//!
//! This module defines the error types used throughout the library.

use thiserror::Error;

/// Errors that can occur when working with HCI sockets
#[derive(Error, Debug)]
pub enum HciError {
    #[error("Failed to open HCI socket: {0}")]
    SocketError(#[from] std::io::Error),

    #[error("Failed to bind to HCI device: {0}")]
    BindError(std::io::Error),

    #[error("Failed to send HCI command: {0}")]
    SendError(std::io::Error),

    #[error("Failed to receive HCI event: {0}")]
    ReceiveError(std::io::Error),

    #[error("Invalid parameter length: {0}")]
    InvalidParamLength(usize),

    #[error("Invalid HCI packet format")]
    InvalidPacketFormat,

    #[error("Unsupported operation")]
    Unsupported,
}

/// General errors that can occur in the library
#[derive(Error, Debug)]
pub enum Error {
    #[error("HCI error: {0}")]
    Hci(#[from] HciError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Not connected")]
    NotConnected,

    #[error("Feature not implemented: {0}")]
    NotImplemented(String),

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Service discovery failed: {0}")]
    ServiceDiscoveryFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Operation timeout")]
    Timeout,
}
