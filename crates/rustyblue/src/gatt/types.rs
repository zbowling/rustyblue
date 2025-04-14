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
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CharacteristicProperty: u8 {
        const BROADCAST = 0x01;
        const READ = 0x02;
        const WRITE_WITHOUT_RESPONSE = 0x04;
        const WRITE = 0x08;
        const NOTIFY = 0x10;
        const INDICATE = 0x20;
        const AUTHENTICATED_SIGNED_WRITES = 0x40;
        const EXTENDED_PROPERTIES = 0x80;
    }
}

impl CharacteristicProperty {
    pub fn can_read(&self) -> bool {
        self.contains(CharacteristicProperty::READ)
    }
    pub fn can_write(&self) -> bool {
        self.contains(CharacteristicProperty::WRITE)
    }
    pub fn can_write_without_response(&self) -> bool {
        self.contains(CharacteristicProperty::WRITE_WITHOUT_RESPONSE)
    }
    pub fn can_notify(&self) -> bool {
        self.contains(CharacteristicProperty::NOTIFY)
    }
    pub fn can_indicate(&self) -> bool {
        self.contains(CharacteristicProperty::INDICATE)
    }
}
