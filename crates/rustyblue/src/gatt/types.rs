//! Common types for GATT operations
//!
//! This module defines the common types used for GATT operations.

use std::fmt;

/// UUID for GATT attributes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Uuid {
    /// 16-bit UUID (actually 16-bit)
    Uuid16(u16),
    /// 32-bit UUID (actually 32-bit)
    Uuid32(u32),
    /// 128-bit UUID (full UUID)
    Uuid128([u8; 16]),
}

impl Uuid {
    /// Convert raw bytes to UUID based on length
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            2 => {
                let uuid = u16::from_le_bytes([bytes[0], bytes[1]]);
                Some(Uuid::Uuid16(uuid))
            }
            4 => {
                let uuid = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Some(Uuid::Uuid32(uuid))
            }
            16 => {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(bytes);
                Some(Uuid::Uuid128(uuid))
            }
            _ => None,
        }
    }
    
    /// Create a UUID from a 16-bit value
    pub fn from_u16(uuid: u16) -> Self {
        Uuid::Uuid16(uuid)
    }
    
    /// Create a UUID from a 32-bit value
    pub fn from_u32(uuid: u32) -> Self {
        Uuid::Uuid32(uuid)
    }
    
    /// Create a UUID from a 128-bit value
    pub fn from_u128(uuid: u128) -> Self {
        let bytes = uuid.to_le_bytes();
        Uuid::Uuid128(bytes)
    }
    
    /// Get the bytes representation of this UUID
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Uuid::Uuid16(uuid) => uuid.to_le_bytes().to_vec(),
            Uuid::Uuid32(uuid) => uuid.to_le_bytes().to_vec(),
            Uuid::Uuid128(uuid) => uuid.to_vec(),
        }
    }
    
    /// Get the 16-bit UUID value if this is a 16-bit UUID
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            Uuid::Uuid16(uuid) => Some(*uuid),
            _ => None,
        }
    }
    
    /// Get the 32-bit UUID value if this is a 32-bit UUID
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Uuid::Uuid32(uuid) => Some(*uuid),
            _ => None,
        }
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Uuid::Uuid16(uuid) => write!(f, "{:04x}", uuid),
            Uuid::Uuid32(uuid) => write!(f, "{:08x}", uuid),
            Uuid::Uuid128(uuid) => {
                write!(
                    f,
                    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    uuid[15], uuid[14], uuid[13], uuid[12],
                    uuid[11], uuid[10],
                    uuid[9], uuid[8],
                    uuid[7], uuid[6],
                    uuid[5], uuid[4], uuid[3], uuid[2], uuid[1], uuid[0]
                )
            }
        }
    }
}

/// Characteristic properties as defined in the Bluetooth specification
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CharacteristicProperty(pub u8);

impl CharacteristicProperty {
    pub const BROADCAST: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const WRITE_WITHOUT_RESPONSE: u8 = 0x04;
    pub const WRITE: u8 = 0x08;
    pub const NOTIFY: u8 = 0x10;
    pub const INDICATE: u8 = 0x20;
    pub const AUTHENTICATED_SIGNED_WRITES: u8 = 0x40;
    pub const EXTENDED_PROPERTIES: u8 = 0x80;
    
    pub fn can_read(&self) -> bool {
        (self.0 & Self::READ) != 0
    }
    
    pub fn can_write(&self) -> bool {
        (self.0 & Self::WRITE) != 0
    }
    
    pub fn can_write_without_response(&self) -> bool {
        (self.0 & Self::WRITE_WITHOUT_RESPONSE) != 0
    }
    
    pub fn can_notify(&self) -> bool {
        (self.0 & Self::NOTIFY) != 0
    }
    
    pub fn can_indicate(&self) -> bool {
        (self.0 & Self::INDICATE) != 0
    }
}

/// A GATT service
#[derive(Debug, Clone)]
pub struct Service {
    /// Service UUID
    pub uuid: Uuid,
    /// Whether this is a primary or secondary service
    pub is_primary: bool,
    /// Start handle for this service
    pub start_handle: u16,
    /// End handle for this service
    pub end_handle: u16,
}

/// A GATT characteristic
#[derive(Debug, Clone)]
pub struct Characteristic {
    /// Characteristic UUID
    pub uuid: Uuid,
    /// Declaration handle
    pub declaration_handle: u16,
    /// Value handle
    pub value_handle: u16,
    /// Characteristic properties
    pub properties: CharacteristicProperty,
}