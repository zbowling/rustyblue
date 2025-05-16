//! Security Manager Protocol (SMP) implementation
//!
//! This module implements the Bluetooth Security Manager Protocol, which is responsible for:
//! - Pairing devices for secure connections
//! - Generating and distributing encryption keys
//! - Authentication of devices
//! - Managing encryption parameters
//!
//! The SMP module provides both LE and Classic Bluetooth security features.

pub mod constants;
pub mod crypto;
pub mod keys;
pub mod manager;
pub mod pairing;
#[cfg(test)]
mod tests;
pub mod types;

// Re-export public API
pub use self::constants::*;
pub use self::keys::KeyStore;
pub use self::keys::*;
pub use self::manager::SmpManager;
pub use self::pairing::*;
pub use self::types::*;
