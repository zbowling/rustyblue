//! GATT protocol implementation
//!
//! This module provides a GATT (Generic Attribute Profile) implementation.

pub mod client;
pub mod server;
pub mod types;

#[cfg(test)]
mod tests;

pub use client::{ConnectionState, GattClient, GattError};
pub use server::{GattServer, GattServerConfig, GattService};
pub use types::{Characteristic, CharacteristicProperty, Service};

// Re-export common types for convenience
pub use crate::uuid::Uuid;
