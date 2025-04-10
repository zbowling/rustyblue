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