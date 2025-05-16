//! L2CAP (Logical Link Control and Adaptation Protocol) implementation
//!
//! This module provides a Bluetooth L2CAP implementation for communication.

pub mod channel;
pub mod constants;
pub mod core;
pub mod packet;
pub mod psm;
pub mod signaling;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export public types and interfaces
pub use self::channel::L2capChannel;
pub use self::core::{ChannelEvent, L2capManager};
pub use self::packet::L2capPacket;
pub use self::psm::PSM;
pub use self::types::{ConnectionPolicy, L2capError, L2capResult, SecurityLevel};
