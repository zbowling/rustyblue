//! L2CAP (Logical Link Control and Adaptation Protocol) implementation
//!
//! This module provides the L2CAP implementation, which is responsible for:
//! - Multiplexing protocol channels over a single physical connection
//! - Segmentation and reassembly of packets
//! - Flow control for each channel
//! - Error control for each channel
//! - Protocol/channel multiplexing

pub mod channel;
pub mod constants;
pub mod core;
pub mod packet;
pub mod psm;
pub mod signaling;
#[cfg(test)]
mod tests;
pub mod types;

// Re-export the public API
pub use self::channel::{L2capChannel, L2capChannelType};
pub use self::core::{ChannelEventCallback, L2capManager};
pub use self::psm::{obtain_dynamic_psm, PSM};
pub use self::types::ConnectionPolicy;
pub use self::types::*;
