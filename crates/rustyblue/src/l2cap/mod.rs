//! L2CAP (Logical Link Control and Adaptation Protocol) implementation
//!
//! This module provides the L2CAP implementation, which is responsible for:
//! - Multiplexing protocol channels over a single physical connection
//! - Segmentation and reassembly of packets
//! - Flow control for each channel
//! - Error control for each channel
//! - Protocol/channel multiplexing

pub mod constants;
pub mod types;
pub mod psm;
pub mod core;
pub mod channel;
pub mod signaling;
pub mod packet;
#[cfg(test)]
mod tests;

// Re-export the public API
pub use self::types::*;
pub use self::core::{L2capManager, ChannelEventCallback};
pub use self::channel::{L2capChannel, L2capChannelType};
pub use self::psm::{PSM, obtain_dynamic_psm};
pub use self::types::ConnectionPolicy;