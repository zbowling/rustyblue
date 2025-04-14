//! Attribute Protocol (ATT) implementation
//!
//! This module provides the ATT protocol implementation, which is the foundation
//! for the GATT (Generic Attribute Profile) layer. ATT defines the client/server
//! architecture and operations for accessing attributes.

pub mod client;
pub mod constants;
pub mod database;
pub mod error;
pub mod server;
pub mod types;
// pub mod pdu; // Assuming pdu module doesn't exist or isn't needed publicly

// Re-export the public API
pub use self::client::AttClient;
pub use self::constants::*;
pub use self::database::{Attribute, AttributeDatabase};
pub use self::error::{AttError, AttErrorCode, AttResult};
pub use self::server::{AttServer, AttServerConfig};
pub use self::types::*; // Ensure types are re-exported
