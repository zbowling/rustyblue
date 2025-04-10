//! Security Manager Protocol (SMP) implementation
//!
//! This module implements the Bluetooth Security Manager Protocol, which is responsible for:
//! - Pairing devices for secure connections
//! - Generating and distributing encryption keys
//! - Authentication of devices
//! - Managing encryption parameters
//! 
//! The SMP module provides both LE and Classic Bluetooth security features.

mod constants;
mod types;
mod keys;
mod pairing;
mod manager;
mod crypto;

// Re-export public API
pub use self::types::*;
pub use self::keys::*;
pub use self::keys::KeyStore;
pub use self::pairing::*;
pub use self::manager::SmpManager;