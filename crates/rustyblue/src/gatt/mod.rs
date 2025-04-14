//! GATT (Generic Attribute Profile) implementation
//!
//! This module provides functionality for interacting with GATT services
//! and characteristics on Bluetooth LE devices.

pub mod client;
pub mod server;
pub mod types;

#[cfg(test)]
mod tests;

pub use client::{ConnectionState, GattClient, GattError};
pub use server::{GattServer, GattServerConfig, GattService};
pub use types::{Characteristic, CharacteristicProperty, Service, Uuid};
