//! Bluetooth HCI (Host Controller Interface) implementation
//!
//! This module provides functionality for interacting with HCI interfaces.

pub mod constants;
pub mod packet;
pub mod socket;
// pub mod types; // Removed - types.rs does not exist
pub mod acl;

#[cfg(test)]
mod tests;

pub use packet::{HciCommand, HciEvent, LeAdvertisingReport};
pub use acl::HciAcl;
pub use socket::HciSocket;
