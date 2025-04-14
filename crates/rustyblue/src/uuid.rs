use rand::RngCore;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::num::ParseIntError;
use std::str::FromStr;

/// Represents a 128-bit Bluetooth UUID.
///
/// This struct handles conversions between 16-bit, 32-bit, and 128-bit Bluetooth UUID formats.
/// Internally, the UUID is always stored as a 128-bit value in little-endian byte order.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct Uuid {
    bytes: [u8; 16],
}

/// The base UUID used for constructing 128-bit UUIDs from 16-bit and 32-bit values.
/// Defined as "00000000-0000-1000-8000-00805F9B34FB" (little-endian representation).
const BASE_UUID_BYTES: [u8; 16] = [
    0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Offset within the base UUID where the 16/32-bit value is inserted.
const BASE_OFFSET: usize = 12;

impl Uuid {
    /// Creates a new 128-bit UUID directly from 16 bytes (little-endian).
    pub const fn from_bytes_le(bytes: [u8; 16]) -> Self {
        Uuid { bytes }
    }

    /// Creates a new 128-bit UUID directly from 16 bytes (big-endian).
    pub fn from_bytes_be(mut bytes: [u8; 16]) -> Self {
        bytes.reverse(); // Convert to little-endian internally
        Uuid { bytes }
    }

    /// Creates a 128-bit UUID from a 16-bit SIG-assigned value.
    /// Formula: `value * 2^96 + BASE_UUID`
    pub const fn from_u16(uuid16: u16) -> Self {
        let mut bytes = BASE_UUID_BYTES;
        bytes[BASE_OFFSET] = uuid16 as u8;
        bytes[BASE_OFFSET + 1] = (uuid16 >> 8) as u8;
        Uuid { bytes }
    }

    /// Creates a 128-bit UUID from a 32-bit SIG-assigned value.
    /// Formula: `value * 2^96 + BASE_UUID`
    pub const fn from_u32(uuid32: u32) -> Self {
        let mut bytes = BASE_UUID_BYTES;
        bytes[BASE_OFFSET] = uuid32 as u8;
        bytes[BASE_OFFSET + 1] = (uuid32 >> 8) as u8;
        bytes[BASE_OFFSET + 2] = (uuid32 >> 16) as u8;
        bytes[BASE_OFFSET + 3] = (uuid32 >> 24) as u8;
        Uuid { bytes }
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
                Some(Uuid::from_bytes_le(bytes))
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

        Uuid { bytes }
    }

    /// Returns the underlying 16 bytes in little-endian order.
    pub const fn as_bytes_le(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Returns the underlying 16 bytes in big-endian order.
    pub fn as_bytes_be(&self) -> [u8; 16] {
        let mut bytes = self.bytes;
        bytes.reverse();
        bytes
    }

    /// Checks if the UUID is derived from the standard Bluetooth base UUID.
    fn is_sig_assigned(&self) -> bool {
        self.bytes[0..BASE_OFFSET] == BASE_UUID_BYTES[0..BASE_OFFSET]
    }

    /// Tries to represent the UUID as a 16-bit value.
    ///
    /// Returns `Some(u16)` if the UUID is a standard SIG-assigned 16-bit UUID,
    /// otherwise returns `None`.
    pub fn as_u16(&self) -> Option<u16> {
        if self.is_sig_assigned()
            && self.bytes[BASE_OFFSET + 2] == 0
            && self.bytes[BASE_OFFSET + 3] == 0
        {
            Some(u16::from_le_bytes([
                self.bytes[BASE_OFFSET],
                self.bytes[BASE_OFFSET + 1],
            ]))
        } else {
            None
        }
    }

    /// Tries to represent the UUID as a 32-bit value.
    ///
    /// Returns `Some(u32)` if the UUID is a standard SIG-assigned 32-bit UUID,
    /// otherwise returns `None`.
    pub fn as_u32(&self) -> Option<u32> {
        if self.is_sig_assigned() {
            Some(u32::from_le_bytes([
                self.bytes[BASE_OFFSET],
                self.bytes[BASE_OFFSET + 1],
                self.bytes[BASE_OFFSET + 2],
                self.bytes[BASE_OFFSET + 3],
            ]))
        } else {
            None
        }
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
        Uuid::from_bytes_le(bytes)
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
        &self.bytes == other
    }
}

impl PartialEq<Uuid> for [u8; 16] {
    fn eq(&self, other: &Uuid) -> bool {
        &other.bytes == self
    }
}

impl<'a> PartialEq<&'a [u8]> for Uuid {
    fn eq(&self, other: &&'a [u8]) -> bool {
        Uuid::try_from_slice_le(other).map_or(false, |uuid| *self == uuid)
    }
}

// --- Hashing ---

impl Hash for Uuid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

// --- Formatting (Display, Debug) --- Placeholder for now
impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Standard hyphenated format (big-endian)
        let b = self.as_bytes_be();
        write!(f, "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show short form if possible, otherwise full hyphenated form
        if let Some(u16_val) = self.as_u16() {
            write!(f, "Uuid(0x{:04X})", u16_val)
        } else if let Some(u32_val) = self.as_u32() {
            // Only show 32-bit if it's not also representable as 16-bit
            if u32_val > u16::MAX as u32 {
                write!(f, "Uuid(0x{:08X})", u32_val)
            } else {
                write!(f, "Uuid(0x{:04X})", u32_val as u16)
            }
        } else {
            fmt::Display::fmt(self, f)
        }
    }
}

// --- Parsing --- Placeholder for now

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
                Ok(Uuid::from_bytes_be(bytes_be))
            }
            _ => Err(UuidParseError::InvalidLength),
        }
    }
}
