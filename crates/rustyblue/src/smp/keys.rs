//! Key management for Security Manager Protocol
//!
//! This module handles the various types of keys used in Bluetooth security,
//! including Long Term Keys (LTK), Identity Resolving Keys (IRK), and
//! Connection Signature Resolving Keys (CSRK).

use super::types::*;
use crate::gap::BdAddr;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Long Term Key (LTK) information
#[derive(Debug, Clone)]
pub struct LongTermKey {
    /// Key value
    pub key: [u8; 16],
    /// EDIV (Encrypted Diversifier)
    pub ediv: u16,
    /// RAND (Random number)
    pub rand: [u8; 8],
    /// Whether this key was generated with Secure Connections pairing
    pub secure_connections: bool,
    /// Authentication level
    pub authenticated: bool,
}

impl LongTermKey {
    /// Create a new Long Term Key
    pub fn new(key: [u8; 16], ediv: u16, rand: [u8; 8], secure_connections: bool, authenticated: bool) -> Self {
        Self {
            key,
            ediv,
            rand,
            secure_connections,
            authenticated,
        }
    }
    
    /// Create an LTK for Secure Connections
    pub fn new_secure_connections(key: [u8; 16], authenticated: bool) -> Self {
        Self {
            key,
            ediv: 0,
            rand: [0; 8],
            secure_connections: true,
            authenticated,
        }
    }
    
    /// Get the security level provided by this key
    pub fn security_level(&self) -> SecurityLevel {
        if self.secure_connections {
            SecurityLevel::SecureConnections
        } else if self.authenticated {
            SecurityLevel::EncryptionWithAuthentication
        } else {
            SecurityLevel::EncryptionOnly
        }
    }
}

/// Identity Resolving Key (IRK)
#[derive(Debug, Clone)]
pub struct IdentityResolvingKey {
    /// Key value
    pub key: [u8; 16],
    /// Identity address type
    pub identity_address_type: u8,
    /// Identity address
    pub identity_address: BdAddr,
}

impl IdentityResolvingKey {
    /// Create a new Identity Resolving Key
    pub fn new(key: [u8; 16], identity_address_type: u8, identity_address: BdAddr) -> Self {
        Self {
            key,
            identity_address_type,
            identity_address,
        }
    }
}

/// Connection Signature Resolving Key (CSRK)
#[derive(Debug, Clone)]
pub struct ConnectionSignatureResolvingKey {
    /// Key value
    pub key: [u8; 16],
    /// Counter for outgoing signed data
    pub sign_counter: u32,
    /// Authentication level
    pub authenticated: bool,
}

impl ConnectionSignatureResolvingKey {
    /// Create a new Connection Signature Resolving Key
    pub fn new(key: [u8; 16], authenticated: bool) -> Self {
        Self {
            key,
            sign_counter: 0,
            authenticated,
        }
    }
    
    /// Increment the signing counter
    pub fn increment_counter(&mut self) -> u32 {
        self.sign_counter += 1;
        self.sign_counter
    }
}

/// Device keys containing all security keys for a device
#[derive(Debug, Clone)]
pub struct DeviceKeys {
    /// Long Term Key
    pub ltk: Option<LongTermKey>,
    /// Identity Resolving Key
    pub irk: Option<IdentityResolvingKey>,
    /// Local Connection Signature Resolving Key
    pub local_csrk: Option<ConnectionSignatureResolvingKey>,
    /// Remote Connection Signature Resolving Key
    pub remote_csrk: Option<ConnectionSignatureResolvingKey>,
    /// Link Key (for BR/EDR)
    pub link_key: Option<[u8; 16]>,
}

impl DeviceKeys {
    /// Create a new empty device keys structure
    pub fn new() -> Self {
        Self {
            ltk: None,
            irk: None,
            local_csrk: None,
            remote_csrk: None,
            link_key: None,
        }
    }
    
    /// Get the security level based on stored keys
    pub fn security_level(&self) -> SecurityLevel {
        if let Some(ltk) = &self.ltk {
            ltk.security_level()
        } else {
            SecurityLevel::None
        }
    }
    
    /// Check if any keys are stored
    pub fn has_keys(&self) -> bool {
        self.ltk.is_some() || self.irk.is_some() || self.local_csrk.is_some() || 
        self.remote_csrk.is_some() || self.link_key.is_some()
    }
}

/// Key Store trait for persistent storage of security keys
pub trait KeyStore {
    /// Save keys for a device
    fn save_keys(&mut self, address: &BdAddr, keys: &DeviceKeys) -> SmpResult<()>;
    
    /// Load keys for a device
    fn load_keys(&self, address: &BdAddr) -> SmpResult<Option<DeviceKeys>>;
    
    /// Delete keys for a device
    fn delete_keys(&mut self, address: &BdAddr) -> SmpResult<()>;
    
    /// Look up device address by Identity Resolving Key
    fn resolve_identity(&self, random_address: &BdAddr) -> SmpResult<Option<BdAddr>>;
    
    /// Get all paired devices
    fn get_paired_devices(&self) -> SmpResult<Vec<BdAddr>>;
}

/// In-memory implementation of KeyStore
#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    /// Device key storage
    keys: RwLock<HashMap<BdAddr, DeviceKeys>>,
}

impl MemoryKeyStore {
    /// Create a new empty in-memory key store
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }
}

impl KeyStore for MemoryKeyStore {
    fn save_keys(&mut self, address: &BdAddr, keys: &DeviceKeys) -> SmpResult<()> {
        let mut store = self.keys.write().unwrap();
        store.insert(*address, keys.clone());
        Ok(())
    }
    
    fn load_keys(&self, address: &BdAddr) -> SmpResult<Option<DeviceKeys>> {
        let store = self.keys.read().unwrap();
        Ok(store.get(address).cloned())
    }
    
    fn delete_keys(&mut self, address: &BdAddr) -> SmpResult<()> {
        let mut store = self.keys.write().unwrap();
        store.remove(address);
        Ok(())
    }
    
    fn resolve_identity(&self, random_address: &BdAddr) -> SmpResult<Option<BdAddr>> {
        // This would actually perform the cryptographic resolution
        // For now we just do a simple lookup
        let store = self.keys.read().unwrap();
        
        // In a real implementation, we would use the IRK to resolve random addresses
        // Here we're just returning None as a placeholder
        Ok(None)
    }
    
    fn get_paired_devices(&self) -> SmpResult<Vec<BdAddr>> {
        let store = self.keys.read().unwrap();
        let devices = store.keys().cloned().collect();
        Ok(devices)
    }
}