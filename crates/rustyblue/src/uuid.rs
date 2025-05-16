//! UUID handling for Bluetooth
//!
//! This module provides functionality for working with Bluetooth UUIDs.

use rand::RngCore;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::num::ParseIntError;
use std::str::FromStr;
use hex;

/// A Bluetooth UUID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid {
    /// The 128-bit UUID value
    pub value: u128,
}

/// The base UUID used for constructing 128-bit UUIDs from 16-bit and 32-bit values.
/// Defined as "00000000-0000-1000-8000-00805F9B34FB" (little-endian representation).
const BASE_UUID_BYTES: [u8; 16] = [
    0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Offset within the base UUID where the 16/32-bit value is inserted.
const BASE_OFFSET: usize = 12;

impl Uuid {
    /// Create a new UUID from a 128-bit value
    pub fn new(value: u128) -> Self {
        Self { value }
    }

    /// Create a new UUID from a 16-bit value (base UUID)
    pub fn from_u16(value: u16) -> Self {
        // Base UUID for 16-bit UUIDs: 0000XXXX-0000-1000-8000-00805F9B34FB
        let base: u128 = 0x00000000_0000_1000_8000_00805F9B34FB;
        Self {
            value: base | (value as u128),
        }
    }

    /// Create a new UUID from a 32-bit value (base UUID)
    pub fn from_u32(value: u32) -> Self {
        // Base UUID for 32-bit UUIDs: XXXXXXXX-0000-1000-8000-00805F9B34FB
        let base: u128 = 0x00000000_0000_1000_8000_00805F9B34FB;
        Self {
            value: base | ((value as u128) << 96),
        }
    }

    /// Tries to create a UUID from a byte slice.
    ///
    /// Accepts slices of length 2 (16-bit), 4 (32-bit), or 16 (128-bit).
    /// Bytes are assumed to be in little-endian order.
    /// Returns `None` if the slice length is invalid.
    pub fn try_from_slice_le(slice: &[u8]) -> Option<Self> {
        match slice.len() {
            2 => {
                let uuid16 = u16::from_le_bytes([slice[0], slice[1]]);
                Some(Uuid::from_u16(uuid16))
            }
            4 => {
                let uuid32 = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
                Some(Uuid::from_u32(uuid32))
            }
            16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(slice);
                Some(Uuid::new(u128::from_le_bytes(bytes)))
            }
            _ => None,
        }
    }

    /// Generates a random (Version 4) UUID.
    pub fn new_random_v4() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);

        // Set version (4) and variant (RFC 4122)
        bytes[7] = (bytes[7] & 0x0F) | 0x40; // version 4
        bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant 1 (RFC 4122)

        // Ensure correct endianness if needed (UUIDs are typically big-endian in standard format)
        // For internal consistency, we keep little-endian based on BASE_UUID
        // Let's adjust for standard v4 representation before storing little-endian
        // V4 format: xxxxxxxx-xxxx-4xxx-axxx-xxxxxxxxxxxx (big-endian)
        // Convert the relevant parts to LE for storage
        bytes[0..4].reverse(); // time_low
        bytes[4..6].reverse(); // time_mid
        bytes[6..8].reverse(); // time_high_and_version
                               // bytes[8..10] (clk_seq_hi_res, clk_seq_low) - usually kept BE
                               // bytes[10..16] (node) - usually kept BE

        Self { value: u128::from_le_bytes(bytes) }
    }

    /// Get the 16-bit value if this is a 16-bit UUID
    pub fn as_u16(&self) -> Option<u16> {
        let base: u128 = 0x00000000_0000_1000_8000_00805F9B34FB;
        if (self.value & !0xFFFF) == base {
            Some((self.value & 0xFFFF) as u16)
        } else {
            None
        }
    }

    /// Get the 32-bit value if this is a 32-bit UUID
    pub fn as_u32(&self) -> Option<u32> {
        let base: u128 = 0x00000000_0000_1000_8000_00805F9B34FB;
        if (self.value & !0xFFFFFFFF_0000_0000_0000_0000_0000_0000) == base {
            Some(((self.value >> 96) & 0xFFFFFFFF) as u32)
        } else {
            None
        }
    }

    /// Get the UUID as a byte array in big-endian order
    pub fn as_bytes_be(&self) -> [u8; 16] {
        self.value.to_be_bytes()
    }

    /// Get the UUID as a byte array in little-endian order
    pub fn as_bytes_le(&self) -> [u8; 16] {
        self.value.to_le_bytes()
    }
}

// --- From Implementations ---

impl From<u16> for Uuid {
    fn from(uuid16: u16) -> Self {
        Uuid::from_u16(uuid16)
    }
}

impl From<u32> for Uuid {
    fn from(uuid32: u32) -> Self {
        Uuid::from_u32(uuid32)
    }
}

impl From<[u8; 16]> for Uuid {
    /// Assumes bytes are in little-endian order.
    fn from(bytes: [u8; 16]) -> Self {
        Self { value: u128::from_le_bytes(bytes) }
    }
}

// --- PartialEq Implementations ---

impl PartialEq<u16> for Uuid {
    fn eq(&self, other: &u16) -> bool {
        self.as_u16() == Some(*other)
    }
}

impl PartialEq<Uuid> for u16 {
    fn eq(&self, other: &Uuid) -> bool {
        other.as_u16() == Some(*self)
    }
}

impl PartialEq<u32> for Uuid {
    fn eq(&self, other: &u32) -> bool {
        self.as_u32() == Some(*other)
    }
}

impl PartialEq<Uuid> for u32 {
    fn eq(&self, other: &Uuid) -> bool {
        other.as_u32() == Some(*self)
    }
}

impl PartialEq<[u8; 16]> for Uuid {
    fn eq(&self, other: &[u8; 16]) -> bool {
        self.value.to_le_bytes() == *other
    }
}

impl PartialEq<Uuid> for [u8; 16] {
    fn eq(&self, other: &Uuid) -> bool {
        other.value.to_le_bytes() == *self
    }
}

impl<'a> PartialEq<&'a [u8]> for Uuid {
    fn eq(&self, other: &&'a [u8]) -> bool {
        Uuid::try_from_slice_le(other).map_or(false, |uuid| *self == uuid)
    }
}

// --- Formatting ---

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.value.to_be_bytes();
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        )
    }
}

// --- Parsing ---

#[derive(Debug)]
pub enum UuidParseError {
    InvalidLength,
    InvalidFormat,
    HexError(hex::FromHexError),
}

impl From<hex::FromHexError> for UuidParseError {
    fn from(err: hex::FromHexError) -> Self {
        UuidParseError::HexError(err)
    }
}

impl From<ParseIntError> for UuidParseError {
    fn from(_: ParseIntError) -> Self {
        UuidParseError::InvalidFormat // Simplified error mapping
    }
}

impl FromStr for Uuid {
    type Err = UuidParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();

        match cleaned.len() {
            4 => {
                // 16-bit short form e.g., "180A"
                let val = u16::from_str_radix(&cleaned, 16)?;
                Ok(Uuid::from_u16(val))
            }
            8 => {
                // 32-bit short form e.g., "0000180A"
                let val = u32::from_str_radix(&cleaned, 16)?;
                Ok(Uuid::from_u32(val))
            }
            32 => {
                // Full 128-bit form without hyphens
                let mut bytes_be = [0u8; 16];
                hex::decode_to_slice(&cleaned, &mut bytes_be)?;
                Ok(Uuid::new(u128::from_be_bytes(bytes_be)))
            }
            _ => Err(UuidParseError::InvalidLength),
        }
    }
}
