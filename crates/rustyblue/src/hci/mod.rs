//! Bluetooth HCI (Host Controller Interface) implementation
//!
//! This module provides functionality for interacting with HCI interfaces.

pub mod constants;
pub mod packet;
pub mod socket;

pub use socket::HciSocket;
pub use packet::{HciCommand, HciEvent, LeAdvertisingReport};
