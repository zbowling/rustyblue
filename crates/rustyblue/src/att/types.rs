//! Type definitions for the ATT protocol
use super::error::{AttError, AttErrorCode, AttResult};
use crate::gap::BdAddr;
use crate::gatt::Uuid;
use super::constants::*;
use std::io::{Cursor, Read, Write};
use std::convert::TryFrom;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

/// ATT Permission flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttPermissions {
    /// Raw permissions value
    raw_value: u16,
}

impl AttPermissions {
    /// Create new permissions with the given raw value
    pub fn new(raw_value: u16) -> Self {
        Self { raw_value }
    }
    
    /// Create empty permissions (no access)
    pub fn none() -> Self {
        Self { raw_value: ATT_PERM_NONE }
    }
    
    /// Create read-only permissions
    pub fn read_only() -> Self {
        Self { raw_value: ATT_PERM_READ }
    }
    
    /// Create write-only permissions
    pub fn write_only() -> Self {
        Self { raw_value: ATT_PERM_WRITE }
    }
    
    /// Create read-write permissions
    pub fn read_write() -> Self {
        Self { raw_value: ATT_PERM_READ | ATT_PERM_WRITE }
    }
    
    /// Create encrypted read-write permissions
    pub fn encrypted() -> Self {
        Self { raw_value: ATT_PERM_READ_ENCRYPTED | ATT_PERM_WRITE_ENCRYPTED }
    }
    
    /// Create authenticated read-write permissions
    pub fn authenticated() -> Self {
        Self { raw_value: ATT_PERM_READ_AUTHENTICATED | ATT_PERM_WRITE_AUTHENTICATED }
    }
    
    /// Create authorized read-write permissions
    pub fn authorized() -> Self {
        Self { raw_value: ATT_PERM_READ_AUTHORIZED | ATT_PERM_WRITE_AUTHORIZED }
    }
    
    /// Create permissions for a given level of security
    pub fn for_security_level(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::None => Self::read_write(),
            SecurityLevel::EncryptionOnly => Self { 
                raw_value: ATT_PERM_READ | ATT_PERM_WRITE | 
                          ATT_PERM_READ_ENCRYPTED | ATT_PERM_WRITE_ENCRYPTED 
            },
            SecurityLevel::EncryptionWithAuthentication => Self { 
                raw_value: ATT_PERM_READ | ATT_PERM_WRITE | 
                          ATT_PERM_READ_ENCRYPTED | ATT_PERM_WRITE_ENCRYPTED |
                          ATT_PERM_READ_AUTHENTICATED | ATT_PERM_WRITE_AUTHENTICATED
            },
            SecurityLevel::SecureConnections => Self { 
                raw_value: ATT_PERM_READ | ATT_PERM_WRITE | 
                          ATT_PERM_READ_ENCRYPTED | ATT_PERM_WRITE_ENCRYPTED |
                          ATT_PERM_READ_AUTHENTICATED | ATT_PERM_WRITE_AUTHENTICATED
            },
        }
    }
    
    /// Get the raw permissions value
    pub fn value(&self) -> u16 {
        self.raw_value
    }
    
    /// Check if read is permitted
    pub fn can_read(&self) -> bool {
        (self.raw_value & ATT_PERM_READ) != 0
    }
    
    /// Check if write is permitted
    pub fn can_write(&self) -> bool {
        (self.raw_value & ATT_PERM_WRITE) != 0
    }
    
    /// Check if read requires encryption
    pub fn read_requires_encryption(&self) -> bool {
        (self.raw_value & ATT_PERM_READ_ENCRYPTED) != 0
    }
    
    /// Check if write requires encryption
    pub fn write_requires_encryption(&self) -> bool {
        (self.raw_value & ATT_PERM_WRITE_ENCRYPTED) != 0
    }
    
    /// Check if read requires authentication
    pub fn read_requires_authentication(&self) -> bool {
        (self.raw_value & ATT_PERM_READ_AUTHENTICATED) != 0
    }
    
    /// Check if write requires authentication
    pub fn write_requires_authentication(&self) -> bool {
        (self.raw_value & ATT_PERM_WRITE_AUTHENTICATED) != 0
    }
    
    /// Check if read requires authorization
    pub fn read_requires_authorization(&self) -> bool {
        (self.raw_value & ATT_PERM_READ_AUTHORIZED) != 0
    }
    
    /// Check if write requires authorization
    pub fn write_requires_authorization(&self) -> bool {
        (self.raw_value & ATT_PERM_WRITE_AUTHORIZED) != 0
    }
    
    /// Get required security level for reading
    pub fn read_security_level(&self) -> SecurityLevel {
        if self.read_requires_authentication() {
            SecurityLevel::EncryptionWithAuthentication
        } else if self.read_requires_encryption() {
            SecurityLevel::EncryptionOnly
        } else {
            SecurityLevel::None
        }
    }
    
    /// Get required security level for writing
    pub fn write_security_level(&self) -> SecurityLevel {
        if self.write_requires_authentication() {
            SecurityLevel::EncryptionWithAuthentication
        } else if self.write_requires_encryption() {
            SecurityLevel::EncryptionOnly
        } else {
            SecurityLevel::None
        }
    }
    
    /// Check if the permissions allow reading with the given security level
    pub fn allows_read_with_security(&self, level: SecurityLevel) -> bool {
        if !self.can_read() {
            return false;
        }
        
        let required = self.read_security_level();
        level >= required
    }
    
    /// Check if the permissions allow writing with the given security level
    pub fn allows_write_with_security(&self, level: SecurityLevel) -> bool {
        if !self.can_write() {
            return false;
        }
        
        let required = self.write_security_level();
        level >= required
    }
}

/// Security level for ATT operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// No security (unencrypted)
    None,
    /// Encryption without authentication
    EncryptionOnly,
    /// Encryption with authentication
    EncryptionWithAuthentication,
    /// Secure Connections with encryption and authentication
    SecureConnections,
}

/// ATT packet formats
pub trait AttPacket: Sized {
    /// Opcode for this packet
    fn opcode() -> u8;
    
    /// Parse packet from bytes
    fn parse(data: &[u8]) -> AttResult<Self>;
    
    /// Serialize packet to bytes
    fn serialize(&self) -> Vec<u8>;
}

/// Error response packet
#[derive(Debug, Clone)]
pub struct ErrorResponse {
    /// Request opcode in error
    pub request_opcode: u8,
    /// Attribute handle in error
    pub handle: u16,
    /// Error code
    pub error_code: AttErrorCode,
}

impl AttPacket for ErrorResponse {
    fn opcode() -> u8 {
        ATT_ERROR_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 5 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let request_opcode = data[1];
        
        let mut cursor = Cursor::new(&data[2..]);
        let handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let error_code = data[4].into();
        
        Ok(Self {
            request_opcode,
            handle,
            error_code,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(5);
        
        packet.push(Self::opcode());
        packet.push(self.request_opcode);
        packet.extend_from_slice(&self.handle.to_le_bytes());
        packet.push(self.error_code.into());
        
        packet
    }
}

impl ErrorResponse {
    /// Create a new error response
    pub fn new(request_opcode: u8, handle: u16, error_code: AttErrorCode) -> Self {
        Self {
            request_opcode,
            handle,
            error_code,
        }
    }
    
    /// Create a new error response from an AttError
    pub fn from_error(request_opcode: u8, error: &AttError) -> Self {
        let handle = error.handle().unwrap_or(0);
        let error_code = error.to_error_code();
        
        Self {
            request_opcode,
            handle,
            error_code,
        }
    }
}

/// Exchange MTU Request packet
#[derive(Debug, Clone)]
pub struct ExchangeMtuRequest {
    /// Client Rx MTU size
    pub client_mtu: u16,
}

impl AttPacket for ExchangeMtuRequest {
    fn opcode() -> u8 {
        ATT_EXCHANGE_MTU_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 3 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let client_mtu = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        Ok(Self { client_mtu })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(3);
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.client_mtu.to_le_bytes());
        
        packet
    }
}

/// Exchange MTU Response packet
#[derive(Debug, Clone)]
pub struct ExchangeMtuResponse {
    /// Server Rx MTU size
    pub server_mtu: u16,
}

impl AttPacket for ExchangeMtuResponse {
    fn opcode() -> u8 {
        ATT_EXCHANGE_MTU_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 3 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let server_mtu = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        Ok(Self { server_mtu })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(3);
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.server_mtu.to_le_bytes());
        
        packet
    }
}

/// Find Information Request packet
#[derive(Debug, Clone)]
pub struct FindInformationRequest {
    /// First requested handle
    pub start_handle: u16,
    /// Last requested handle
    pub end_handle: u16,
}

impl AttPacket for FindInformationRequest {
    fn opcode() -> u8 {
        ATT_FIND_INFO_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 5 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let start_handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let end_handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        Ok(Self {
            start_handle,
            end_handle,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(5);
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.start_handle.to_le_bytes());
        packet.extend_from_slice(&self.end_handle.to_le_bytes());
        
        packet
    }
}

/// Handle-UUID pair in Find Information Response
#[derive(Debug, Clone)]
pub enum HandleUuidPair {
    /// 16-bit UUID
    Uuid16(u16, u16),
    /// 128-bit UUID
    Uuid128(u16, Uuid),
}

/// Find Information Response packet
#[derive(Debug, Clone)]
pub struct FindInformationResponse {
    /// Format of information data
    pub format: u8,
    /// List of handle-UUID pairs
    pub information_data: Vec<HandleUuidPair>,
}

impl AttPacket for FindInformationResponse {
    fn opcode() -> u8 {
        ATT_FIND_INFO_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 2 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let format = data[1];
        let information_data = Self::parse_pairs(format, &data[2..])?;
        
        Ok(Self {
            format,
            information_data,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        
        packet.push(Self::opcode());
        packet.push(self.format);
        
        packet.extend_from_slice(&Self::serialize_pairs(&self.information_data));
        
        packet
    }

    fn parse_pairs(format: u8, data: &[u8]) -> AttResult<Vec<HandleUuidPair>> {
        let mut information_data = Vec::new();
        let mut current_pos = 0;
        if format == ATT_FIND_INFO_RSP_FORMAT_16BIT {
            let pair_size = 4; // 2 handle + 2 UUID
            while current_pos + pair_size <= data.len() {
                let handle = u16::from_le_bytes([data[current_pos], data[current_pos + 1]]);
                let uuid16 = u16::from_le_bytes([data[current_pos + 2], data[current_pos + 3]]);
                information_data.push(HandleUuidPair::Uuid16(handle, uuid16));
                current_pos += pair_size;
            }
        } else if format == ATT_FIND_INFO_RSP_FORMAT_128BIT {
            let pair_size = 18; // 2 handle + 16 UUID
            while current_pos + pair_size <= data.len() {
                let handle = u16::from_le_bytes([data[current_pos], data[current_pos + 1]]);
                let mut uuid_bytes = [0u8; 16];
                uuid_bytes.copy_from_slice(&data[current_pos + 2..current_pos + 18]);
                let uuid_opt = Uuid::from_bytes(&uuid_bytes);
                let uuid = uuid_opt.ok_or(AttError::InvalidPdu)?;
                information_data.push(HandleUuidPair::Uuid128(handle, uuid));
                current_pos += pair_size;
            }
        } else {
            return Err(AttError::InvalidPdu);
        }
        Ok(information_data)
    }
    
    fn serialize_pairs(pairs: &[HandleUuidPair]) -> Vec<u8> {
        let mut data = Vec::new();
        if pairs.is_empty() { return data; }

        let format = match pairs[0] {
            HandleUuidPair::Uuid16(_, _) => ATT_FIND_INFO_RSP_FORMAT_16BIT,
            HandleUuidPair::Uuid128(_, _) => ATT_FIND_INFO_RSP_FORMAT_128BIT,
        };
        data.push(format);

        for pair in pairs {
            match pair {
                HandleUuidPair::Uuid16(handle, uuid16) => {
                    if format != ATT_FIND_INFO_RSP_FORMAT_16BIT { continue; }
                    data.extend_from_slice(&handle.to_le_bytes());
                    data.extend_from_slice(&uuid16.to_le_bytes());
                }
                HandleUuidPair::Uuid128(handle, ref uuid) => {
                    if format != ATT_FIND_INFO_RSP_FORMAT_128BIT { continue; }
                    data.extend_from_slice(&handle.to_le_bytes());
                    data.extend_from_slice(&uuid.as_bytes()); 
                }
            }
        }
        data
    }
}

/// Find By Type Value Request packet
#[derive(Debug, Clone)]
pub struct FindByTypeValueRequest {
    /// First requested handle
    pub start_handle: u16,
    /// Last requested handle
    pub end_handle: u16,
    /// Attribute type (must be 16-bit UUID)
    pub attribute_type: u16,
    /// Attribute value to match
    pub attribute_value: Vec<u8>,
}

impl AttPacket for FindByTypeValueRequest {
    fn opcode() -> u8 {
        ATT_FIND_BY_TYPE_VALUE_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 7 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let start_handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let end_handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let attribute_type = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let attribute_value = data[7..].to_vec();
        
        Ok(Self {
            start_handle,
            end_handle,
            attribute_type,
            attribute_value,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(7 + self.attribute_value.len());
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.start_handle.to_le_bytes());
        packet.extend_from_slice(&self.end_handle.to_le_bytes());
        packet.extend_from_slice(&self.attribute_type.to_le_bytes());
        packet.extend_from_slice(&self.attribute_value);
        
        packet
    }
}

/// Handle range in Find By Type Value Response
#[derive(Debug, Clone)]
pub struct HandleRange {
    /// Found handle
    pub found_handle: u16,
    /// Group end handle
    pub group_end_handle: u16,
}

/// Find By Type Value Response packet
#[derive(Debug, Clone)]
pub struct FindByTypeValueResponse {
    /// List of handle ranges
    pub handles: Vec<HandleRange>,
}

impl AttPacket for FindByTypeValueResponse {
    fn opcode() -> u8 {
        ATT_FIND_BY_TYPE_VALUE_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 1 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut handles = Vec::new();
        let mut offset = 1;
        
        while offset + 4 <= data.len() {
            let mut cursor = Cursor::new(&data[offset..]);
            let found_handle = cursor.read_u16::<LittleEndian>()
                .map_err(|_| AttError::InvalidPdu)?;
                
            let group_end_handle = cursor.read_u16::<LittleEndian>()
                .map_err(|_| AttError::InvalidPdu)?;
                
            handles.push(HandleRange {
                found_handle,
                group_end_handle,
            });
            
            offset += 4;
        }
        
        Ok(Self { handles })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(1 + self.handles.len() * 4);
        
        packet.push(Self::opcode());
        
        for range in &self.handles {
            packet.extend_from_slice(&range.found_handle.to_le_bytes());
            packet.extend_from_slice(&range.group_end_handle.to_le_bytes());
        }
        
        packet
    }
}

/// Read By Type Request packet
#[derive(Debug, Clone)]
pub struct ReadByTypeRequest {
    /// First requested handle
    pub start_handle: u16,
    /// Last requested handle
    pub end_handle: u16,
    /// Attribute type UUID
    pub attribute_type: Uuid,
}

impl AttPacket for ReadByTypeRequest {
    fn opcode() -> u8 {
        ATT_READ_BY_TYPE_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 7 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let start_handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let end_handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        // Check attribute type UUID format
        let attribute_type = if data.len() == 7 {
            // 16-bit UUID
            let mut cursor = Cursor::new(&data[5..]);
            let uuid16 = cursor.read_u16::<LittleEndian>()
                .map_err(|_| AttError::InvalidPdu)?;
                
            Uuid::from_u16(uuid16)
        } else if data.len() == 21 {
            // 128-bit UUID
            let mut uuid_bytes = [0u8; 16];
            uuid_bytes.copy_from_slice(&data[5..21]);
            Uuid::from_bytes(uuid_bytes)
        } else {
            return Err(AttError::InvalidPdu);
        };
        
        Ok(Self {
            start_handle,
            end_handle,
            attribute_type,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.start_handle.to_le_bytes());
        packet.extend_from_slice(&self.end_handle.to_le_bytes());
        
        if let Some(uuid16) = self.attribute_type.as_u16() {
            // 16-bit UUID
            packet.extend_from_slice(&uuid16.to_le_bytes());
        } else {
            // 128-bit UUID
            packet.extend_from_slice(self.attribute_type.as_bytes());
        }
        
        packet
    }
}

/// Handle and value in Read By Type Response
#[derive(Debug, Clone)]
pub struct HandleValue {
    /// Attribute handle
    pub handle: u16,
    /// Attribute value
    pub value: Vec<u8>,
}

/// Read By Type Response packet
#[derive(Debug, Clone)]
pub struct ReadByTypeResponse {
    /// Length of each item
    pub length: u8,
    /// List of handle-value pairs
    pub data: Vec<HandleValue>,
}

impl AttPacket for ReadByTypeResponse {
    fn opcode() -> u8 {
        ATT_READ_BY_TYPE_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 2 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let length = data[1];
        if length < 2 {
            return Err(AttError::InvalidPdu);
        }
        
        let mut data_list = Vec::new();
        let mut offset = 2;
        
        while offset + length as usize <= data.len() {
            let mut cursor = Cursor::new(&data[offset..]);
            let handle = cursor.read_u16::<LittleEndian>()
                .map_err(|_| AttError::InvalidPdu)?;
                
            let _value_size = length as usize - 2;
            let value = data[offset + 2..offset + length as usize].to_vec();
            
            data_list.push(HandleValue {
                handle,
                value,
            });
            
            offset += length as usize;
        }
        
        Ok(Self {
            length,
            data: data_list,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        
        packet.push(Self::opcode());
        packet.push(self.length);
        
        for item in &self.data {
            packet.extend_from_slice(&item.handle.to_le_bytes());
            packet.extend_from_slice(&item.value);
        }
        
        packet
    }
}

/// Read Request packet
#[derive(Debug, Clone)]
pub struct ReadRequest {
    /// Handle to read
    pub handle: u16,
}

impl AttPacket for ReadRequest {
    fn opcode() -> u8 {
        ATT_READ_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 3 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        Ok(Self { handle })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(3);
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.handle.to_le_bytes());
        
        packet
    }
}

/// Read Response packet
#[derive(Debug, Clone)]
pub struct ReadResponse {
    /// Attribute value
    pub value: Vec<u8>,
}

impl AttPacket for ReadResponse {
    fn opcode() -> u8 {
        ATT_READ_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 1 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let value = data[1..].to_vec();
        
        Ok(Self { value })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(1 + self.value.len());
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.value);
        
        packet
    }
}

/// Read Blob Request packet
#[derive(Debug, Clone)]
pub struct ReadBlobRequest {
    /// Handle to read
    pub handle: u16,
    /// Offset to start reading from
    pub offset: u16,
}

impl AttPacket for ReadBlobRequest {
    fn opcode() -> u8 {
        ATT_READ_BLOB_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 5 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let offset = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        Ok(Self {
            handle,
            offset,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(5);
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.handle.to_le_bytes());
        packet.extend_from_slice(&self.offset.to_le_bytes());
        
        packet
    }
}

/// Read Blob Response packet
#[derive(Debug, Clone)]
pub struct ReadBlobResponse {
    /// Attribute value part
    pub value: Vec<u8>,
}

impl AttPacket for ReadBlobResponse {
    fn opcode() -> u8 {
        ATT_READ_BLOB_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 1 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let value = data[1..].to_vec();
        
        Ok(Self { value })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(1 + self.value.len());
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.value);
        
        packet
    }
}

/// Read Multiple Request packet
#[derive(Debug, Clone)]
pub struct ReadMultipleRequest {
    /// Set of handles to read
    pub handles: Vec<u16>,
}

impl AttPacket for ReadMultipleRequest {
    fn opcode() -> u8 {
        ATT_READ_MULTIPLE_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 3 || data[0] != Self::opcode() || (data.len() - 1) % 2 != 0 {
            return Err(AttError::InvalidPdu);
        }
        
        let mut handles = Vec::new();
        let mut offset = 1;
        
        while offset + 2 <= data.len() {
            let mut cursor = Cursor::new(&data[offset..]);
            let handle = cursor.read_u16::<LittleEndian>()
                .map_err(|_| AttError::InvalidPdu)?;
                
            handles.push(handle);
            offset += 2;
        }
        
        Ok(Self { handles })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(1 + self.handles.len() * 2);
        
        packet.push(Self::opcode());
        
        for handle in &self.handles {
            packet.extend_from_slice(&handle.to_le_bytes());
        }
        
        packet
    }
}

/// Read Multiple Response packet
#[derive(Debug, Clone)]
pub struct ReadMultipleResponse {
    /// Set of values
    pub values: Vec<u8>,
}

impl AttPacket for ReadMultipleResponse {
    fn opcode() -> u8 {
        ATT_READ_MULTIPLE_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 1 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let values = data[1..].to_vec();
        
        Ok(Self { values })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(1 + self.values.len());
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.values);
        
        packet
    }
}

/// Read By Group Type Request packet
#[derive(Debug, Clone)]
pub struct ReadByGroupTypeRequest {
    /// First requested handle
    pub start_handle: u16,
    /// Last requested handle
    pub end_handle: u16,
    /// Group type UUID
    pub group_type: Uuid,
}

impl AttPacket for ReadByGroupTypeRequest {
    fn opcode() -> u8 {
        ATT_READ_BY_GROUP_TYPE_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 7 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let start_handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let end_handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        // Check group type UUID format
        let group_type = if data.len() == 7 {
            // 16-bit UUID
            let mut cursor = Cursor::new(&data[5..]);
            let uuid16 = cursor.read_u16::<LittleEndian>()
                .map_err(|_| AttError::InvalidPdu)?;
                
            Uuid::from_u16(uuid16)
        } else if data.len() == 21 {
            // 128-bit UUID
            let mut uuid_bytes = [0u8; 16];
            uuid_bytes.copy_from_slice(&data[5..21]);
            Uuid::from_bytes(uuid_bytes)
        } else {
            return Err(AttError::InvalidPdu);
        };
        
        Ok(Self {
            start_handle,
            end_handle,
            group_type,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.start_handle.to_le_bytes());
        packet.extend_from_slice(&self.end_handle.to_le_bytes());
        
        if let Some(uuid16) = self.group_type.as_u16() {
            // 16-bit UUID
            packet.extend_from_slice(&uuid16.to_le_bytes());
        } else {
            // 128-bit UUID
            packet.extend_from_slice(self.group_type.as_bytes());
        }
        
        packet
    }
}

/// Attribute data in Read By Group Type Response
#[derive(Debug, Clone)]
pub struct AttributeData {
    /// Attribute handle
    pub handle: u16,
    /// Group end handle
    pub end_group_handle: u16,
    /// Attribute value
    pub value: Vec<u8>,
}

/// Read By Group Type Response packet
#[derive(Debug, Clone)]
pub struct ReadByGroupTypeResponse {
    /// Length of each item
    pub length: u8,
    /// List of attribute data
    pub data: Vec<AttributeData>,
}

impl AttPacket for ReadByGroupTypeResponse {
    fn opcode() -> u8 {
        ATT_READ_BY_GROUP_TYPE_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 2 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let length = data[1];
        if length < 6 {
            return Err(AttError::InvalidPdu);
        }
        
        let mut data_list = Vec::new();
        let mut offset = 2;
        
        while offset + length as usize <= data.len() {
            let mut cursor = Cursor::new(&data[offset..]);
            let handle = cursor.read_u16::<LittleEndian>()
                .map_err(|_| AttError::InvalidPdu)?;
                
            let end_group_handle = cursor.read_u16::<LittleEndian>()
                .map_err(|_| AttError::InvalidPdu)?;
                
            let _value_size = length as usize - 4;
            let value = data[offset + 4..offset + length as usize].to_vec();
            
            data_list.push(AttributeData {
                handle,
                end_group_handle,
                value,
            });
            
            offset += length as usize;
        }
        
        Ok(Self {
            length,
            data: data_list,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        
        packet.push(Self::opcode());
        packet.push(self.length);
        
        for item in &self.data {
            packet.extend_from_slice(&item.handle.to_le_bytes());
            packet.extend_from_slice(&item.end_group_handle.to_le_bytes());
            packet.extend_from_slice(&item.value);
        }
        
        packet
    }
}

/// Write Request packet
#[derive(Debug, Clone)]
pub struct WriteRequest {
    /// Handle to write
    pub handle: u16,
    /// Value to write
    pub value: Vec<u8>,
}

impl AttPacket for WriteRequest {
    fn opcode() -> u8 {
        ATT_WRITE_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 3 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let value = data[3..].to_vec();
        
        Ok(Self {
            handle,
            value,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(3 + self.value.len());
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.handle.to_le_bytes());
        packet.extend_from_slice(&self.value);
        
        packet
    }
}

/// Write Response packet
#[derive(Debug, Clone)]
pub struct WriteResponse;

impl AttPacket for WriteResponse {
    fn opcode() -> u8 {
        ATT_WRITE_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 1 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        Ok(Self)
    }
    
    fn serialize(&self) -> Vec<u8> {
        vec![Self::opcode()]
    }
}

/// Write Command packet
#[derive(Debug, Clone)]
pub struct WriteCommand {
    /// Handle to write
    pub handle: u16,
    /// Value to write
    pub value: Vec<u8>,
}

impl AttPacket for WriteCommand {
    fn opcode() -> u8 {
        ATT_WRITE_CMD
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 3 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let value = data[3..].to_vec();
        
        Ok(Self {
            handle,
            value,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(3 + self.value.len());
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.handle.to_le_bytes());
        packet.extend_from_slice(&self.value);
        
        packet
    }
}

/// Prepare Write Request packet
#[derive(Debug, Clone)]
pub struct PrepareWriteRequest {
    /// Handle to write
    pub handle: u16,
    /// Offset to write at
    pub offset: u16,
    /// Part of the value to write
    pub value: Vec<u8>,
}

impl AttPacket for PrepareWriteRequest {
    fn opcode() -> u8 {
        ATT_PREPARE_WRITE_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 5 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let offset = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let value = data[5..].to_vec();
        
        Ok(Self {
            handle,
            offset,
            value,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(5 + self.value.len());
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.handle.to_le_bytes());
        packet.extend_from_slice(&self.offset.to_le_bytes());
        packet.extend_from_slice(&self.value);
        
        packet
    }
}

/// Prepare Write Response packet
#[derive(Debug, Clone)]
pub struct PrepareWriteResponse {
    /// Handle being written
    pub handle: u16,
    /// Offset being written
    pub offset: u16,
    /// Part of the value being written
    pub value: Vec<u8>,
}

impl AttPacket for PrepareWriteResponse {
    fn opcode() -> u8 {
        ATT_PREPARE_WRITE_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 5 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let offset = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let value = data[5..].to_vec();
        
        Ok(Self {
            handle,
            offset,
            value,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(5 + self.value.len());
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.handle.to_le_bytes());
        packet.extend_from_slice(&self.offset.to_le_bytes());
        packet.extend_from_slice(&self.value);
        
        packet
    }
}

/// Execute Write Request packet
#[derive(Debug, Clone)]
pub struct ExecuteWriteRequest {
    /// Flags
    pub flags: u8,
}

impl AttPacket for ExecuteWriteRequest {
    fn opcode() -> u8 {
        ATT_EXECUTE_WRITE_REQ
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 2 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let flags = data[1];
        
        Ok(Self { flags })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(2);
        
        packet.push(Self::opcode());
        packet.push(self.flags);
        
        packet
    }
}

/// Execute Write Response packet
#[derive(Debug, Clone)]
pub struct ExecuteWriteResponse;

impl AttPacket for ExecuteWriteResponse {
    fn opcode() -> u8 {
        ATT_EXECUTE_WRITE_RSP
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 1 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        Ok(Self)
    }
    
    fn serialize(&self) -> Vec<u8> {
        vec![Self::opcode()]
    }
}

/// Handle Value Notification packet
#[derive(Debug, Clone)]
pub struct HandleValueNotification {
    /// Handle of the attribute
    pub handle: u16,
    /// Attribute value
    pub value: Vec<u8>,
}

impl AttPacket for HandleValueNotification {
    fn opcode() -> u8 {
        ATT_HANDLE_VALUE_NTF
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 3 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let value = data[3..].to_vec();
        
        Ok(Self {
            handle,
            value,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(3 + self.value.len());
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.handle.to_le_bytes());
        packet.extend_from_slice(&self.value);
        
        packet
    }
}

/// Handle Value Indication packet
#[derive(Debug, Clone)]
pub struct HandleValueIndication {
    /// Handle of the attribute
    pub handle: u16,
    /// Attribute value
    pub value: Vec<u8>,
}

impl AttPacket for HandleValueIndication {
    fn opcode() -> u8 {
        ATT_HANDLE_VALUE_IND
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 3 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        let mut cursor = Cursor::new(&data[1..]);
        let handle = cursor.read_u16::<LittleEndian>()
            .map_err(|_| AttError::InvalidPdu)?;
            
        let value = data[3..].to_vec();
        
        Ok(Self {
            handle,
            value,
        })
    }
    
    fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(3 + self.value.len());
        
        packet.push(Self::opcode());
        packet.extend_from_slice(&self.handle.to_le_bytes());
        packet.extend_from_slice(&self.value);
        
        packet
    }
}

/// Handle Value Confirmation packet
#[derive(Debug, Clone)]
pub struct HandleValueConfirmation;

impl AttPacket for HandleValueConfirmation {
    fn opcode() -> u8 {
        ATT_HANDLE_VALUE_CONF
    }
    
    fn parse(data: &[u8]) -> AttResult<Self> {
        if data.len() < 1 || data[0] != Self::opcode() {
            return Err(AttError::InvalidPdu);
        }
        
        Ok(Self)
    }
    
    fn serialize(&self) -> Vec<u8> {
        vec![Self::opcode()]
    }
}

/// Parse an ATT packet from raw bytes
pub fn parse_att_packet(data: &[u8]) -> AttResult<(u8, Vec<u8>)> {
    if data.is_empty() {
        return Err(AttError::InvalidPdu);
    }
    
    let opcode = data[0];
    let packet_data = data.to_vec();
    
    Ok((opcode, packet_data))
}