//! Attribute Protocol (ATT) implementation
//!
//! This module provides the ATT protocol implementation, which is the foundation
//! for the GATT (Generic Attribute Profile) layer. ATT defines the client/server
//! architecture and operations for accessing attributes.

pub mod constants;
pub mod types;
pub mod client;
pub mod server;
pub mod database;
pub mod error;
// pub mod pdu; // Assuming pdu module doesn't exist or isn't needed publicly

// Re-export the public API
pub use self::constants::*;
pub use self::types::*; // Ensure types are re-exported
pub use self::client::AttClient;
pub use self::server::{AttServer, AttServerConfig};
pub use self::database::{AttributeDatabase, Attribute};
pub use self::error::{AttError, AttErrorCode, AttResult};