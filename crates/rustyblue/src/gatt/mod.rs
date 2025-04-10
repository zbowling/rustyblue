//! GATT (Generic Attribute Profile) implementation
//!
//! This module provides functionality for interacting with GATT services
//! and characteristics on Bluetooth LE devices.

pub mod client;
mod types;

pub use client::{GattClient, GattError};
pub use types::{Service, Characteristic, CharacteristicProperty, Uuid};