//! Common types for GATT operations
//!
//! This module defines the common types used for GATT operations.

use crate::uuid::Uuid;
use bitflags::bitflags;
use std::fmt;

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

bitflags! {
    /// Characteristic properties as defined in the Bluetooth specification
    pub struct CharacteristicProperty: u8 {
        /// Characteristic supports broadcasting
        const BROADCAST = 0x01;
        /// Characteristic is readable
        const READ = 0x02;
        /// Characteristic can be written without response
        const WRITE_WITHOUT_RESPONSE = 0x04;
        /// Characteristic can be written
        const WRITE = 0x08;
        /// Characteristic supports notifications
        const NOTIFY = 0x10;
        /// Characteristic supports indications
        const INDICATE = 0x20;
        /// Characteristic supports signed writes
        const AUTHENTICATED_SIGNED_WRITES = 0x40;
        /// Characteristic has extended properties
        const EXTENDED_PROPERTIES = 0x80;
    }
}

impl CharacteristicProperty {
    /// Check if the READ property is set
    pub fn can_read(&self) -> bool {
        self.contains(CharacteristicProperty::READ)
    }
    
    /// Check if the WRITE property is set
    pub fn can_write(&self) -> bool {
        self.contains(CharacteristicProperty::WRITE)
    }
    
    /// Check if the WRITE_WITHOUT_RESPONSE property is set
    pub fn can_write_without_response(&self) -> bool {
        self.contains(CharacteristicProperty::WRITE_WITHOUT_RESPONSE)
    }
    
    /// Check if the NOTIFY property is set
    pub fn can_notify(&self) -> bool {
        self.contains(CharacteristicProperty::NOTIFY)
    }
    
    /// Check if the INDICATE property is set
    pub fn can_indicate(&self) -> bool {
        self.contains(CharacteristicProperty::INDICATE)
    }
}
