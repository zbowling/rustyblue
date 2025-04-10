//! Attribute database implementation for ATT server
use super::error::{AttError, AttErrorCode, AttResult};
use super::types::{SecurityLevel, AttPermissions};
use super::constants::*;
use crate::gatt::Uuid;
use std::sync::{Arc, RwLock};
use std::collections::BTreeMap;

/// An attribute in the database
#[derive(Debug, Clone)]
pub struct Attribute {
    /// Attribute handle
    pub handle: u16,
    /// Attribute type (UUID)
    pub type_: Uuid,
    /// Attribute value
    pub value: Vec<u8>,
    /// Attribute permissions
    pub permissions: AttPermissions,
}

impl Attribute {
    /// Create a new attribute
    pub fn new(handle: u16, type_: Uuid, value: Vec<u8>, permissions: AttPermissions) -> Self {
        Self {
            handle,
            type_,
            value,
            permissions,
        }
    }
    
    /// Check if this attribute can be read with the given security level
    pub fn can_read(&self, security_level: SecurityLevel) -> bool {
        self.permissions.allows_read_with_security(security_level)
    }
    
    /// Check if this attribute can be written with the given security level
    pub fn can_write(&self, security_level: SecurityLevel) -> bool {
        self.permissions.allows_write_with_security(security_level)
    }
    
    /// Read the attribute value
    pub fn read(&self, security_level: SecurityLevel) -> AttResult<&[u8]> {
        if !self.can_read(security_level) {
            if self.permissions.read_requires_authentication() && 
               security_level < SecurityLevel::EncryptionWithAuthentication {
                return Err(AttError::InsufficientAuthentication);
            } else if self.permissions.read_requires_encryption() && 
                    security_level < SecurityLevel::EncryptionOnly {
                return Err(AttError::InsufficientEncryption);
            } else if self.permissions.read_requires_authorization() {
                return Err(AttError::InsufficientAuthorization);
            } else {
                return Err(AttError::ReadNotPermitted);
            }
        }
        
        Ok(&self.value)
    }
    
    /// Write to the attribute value
    pub fn write(&mut self, value: &[u8], security_level: SecurityLevel) -> AttResult<()> {
        if !self.can_write(security_level) {
            if self.permissions.write_requires_authentication() && 
               security_level < SecurityLevel::EncryptionWithAuthentication {
                return Err(AttError::InsufficientAuthentication);
            } else if self.permissions.write_requires_encryption() && 
                    security_level < SecurityLevel::EncryptionOnly {
                return Err(AttError::InsufficientEncryption);
            } else if self.permissions.write_requires_authorization() {
                return Err(AttError::InsufficientAuthorization);
            } else {
                return Err(AttError::WriteNotPermitted);
            }
        }
        
        self.value = value.to_vec();
        Ok(())
    }
}

/// Attribute write callback
pub type AttributeWriteCallback = Arc<dyn Fn(u16, &[u8]) -> AttResult<()> + Send + Sync>;

/// Attribute read callback
pub type AttributeReadCallback = Arc<dyn Fn(u16) -> AttResult<Vec<u8>> + Send + Sync>;

/// Attribute database
pub struct AttributeDatabase {
    /// Map of handles to attributes
    attributes: RwLock<BTreeMap<u16, Attribute>>,
    /// Map of handles to write callbacks
    write_callbacks: RwLock<BTreeMap<u16, AttributeWriteCallback>>,
    /// Map of handles to read callbacks
    read_callbacks: RwLock<BTreeMap<u16, AttributeReadCallback>>,
    /// Next available handle
    next_handle: RwLock<u16>,
}

impl AttributeDatabase {
    /// Create a new empty attribute database
    pub fn new() -> Self {
        Self {
            attributes: RwLock::new(BTreeMap::new()),
            write_callbacks: RwLock::new(BTreeMap::new()),
            read_callbacks: RwLock::new(BTreeMap::new()),
            next_handle: RwLock::new(ATT_HANDLE_MIN),
        }
    }
    
    /// Add an attribute to the database
    pub fn add_attribute(&self, attr: Attribute) -> AttResult<u16> {
        let handle = attr.handle;
        
        // Check for duplicate handle
        let mut attributes = self.attributes.write().unwrap();
        if attributes.contains_key(&handle) {
            return Err(AttError::InvalidParameter(format!("Duplicate handle: {}", handle)));
        }
        
        // Update next_handle if needed
        if handle >= *self.next_handle.read().unwrap() {
            *self.next_handle.write().unwrap() = handle + 1;
        }
        
        // Add the attribute
        attributes.insert(handle, attr);
        
        Ok(handle)
    }
    
    /// Add an attribute with the next available handle
    pub fn add_attribute_with_next_handle(
        &self,
        type_: Uuid,
        value: Vec<u8>,
        permissions: AttPermissions
    ) -> AttResult<u16> {
        let handle = *self.next_handle.read().unwrap();
        
        // Create and add the attribute
        let attr = Attribute::new(handle, type_, value, permissions);
        self.add_attribute(attr)?;
        
        Ok(handle)
    }
    
    /// Register a write callback for a handle
    pub fn register_write_callback(
        &self,
        handle: u16,
        callback: AttributeWriteCallback
    ) -> AttResult<()> {
        let mut callbacks = self.write_callbacks.write().unwrap();
        
        // Check if the attribute exists
        let attributes = self.attributes.read().unwrap();
        if !attributes.contains_key(&handle) {
            return Err(AttError::InvalidHandle(handle));
        }
        
        callbacks.insert(handle, callback);
        
        Ok(())
    }
    
    /// Register a read callback for a handle
    pub fn register_read_callback(
        &self,
        handle: u16,
        callback: AttributeReadCallback
    ) -> AttResult<()> {
        let mut callbacks = self.read_callbacks.write().unwrap();
        
        // Check if the attribute exists
        let attributes = self.attributes.read().unwrap();
        if !attributes.contains_key(&handle) {
            return Err(AttError::InvalidHandle(handle));
        }
        
        callbacks.insert(handle, callback);
        
        Ok(())
    }
    
    /// Find attributes in a range by type
    pub fn find_by_type(
        &self,
        start_handle: u16,
        end_handle: u16,
        type_: &Uuid,
        security_level: SecurityLevel
    ) -> AttResult<Vec<Attribute>> {
        let attributes = self.attributes.read().unwrap();
        let mut results = Vec::new();
        
        for (_handle, attr) in attributes.range(start_handle..=end_handle) {
            if attr.type_ == *type_ && attr.can_read(security_level) {
                // Clone the attribute to avoid referencing the attributes map
                results.push(Attribute {
                    handle: attr.handle,
                    type_: attr.type_.clone(),
                    permissions: attr.permissions,
                    value: attr.value.clone(),
                });
            }
        }
        
        Ok(results)
    }
    
    /// Find attributes in a range by type and value
    pub fn find_by_type_value(
        &self,
        start_handle: u16,
        end_handle: u16,
        type_: &Uuid,
        value: &[u8],
        security_level: SecurityLevel
    ) -> AttResult<Vec<(u16, u16)>> {
        let attributes = self.attributes.read().unwrap();
        let mut results = Vec::new();
        
        // Iterate through attributes in range
        let mut group_start: Option<u16> = None;
        let mut prev_handle: Option<u16> = None;
        
        for (&handle, attr) in attributes.range(start_handle..=end_handle) {
            if attr.type_ == *type_ && attr.can_read(security_level) {
                match attr.read(security_level) {
                    Ok(attr_value) if attr_value == value => {
                        // Found a matching attribute
                        if group_start.is_none() {
                            group_start = Some(handle);
                        }
                    },
                    _ => {
                        // Non-matching attribute
                        if let Some(start) = group_start {
                            if let Some(prev) = prev_handle {
                                results.push((start, prev));
                            }
                            group_start = None;
                        }
                    }
                }
                
                prev_handle = Some(handle);
            }
        }
        
        // Handle the last group if needed
        if let Some(start) = group_start {
            if let Some(prev) = prev_handle {
                results.push((start, prev));
            }
        }
        
        Ok(results)
    }
    
    /// Find attribute information in a range
    pub fn find_information(
        &self,
        start_handle: u16,
        end_handle: u16,
        security_level: SecurityLevel
    ) -> AttResult<Vec<(u16, Uuid)>> {
        let attributes = self.attributes.read().unwrap();
        let mut results = Vec::new();
        
        for (&handle, attr) in attributes.range(start_handle..=end_handle) {
            if attr.can_read(security_level) {
                results.push((handle, attr.type_.clone()));
            }
        }
        
        Ok(results)
    }
    
    /// Read an attribute value by handle
    pub fn read_by_handle(
        &self,
        handle: u16,
        security_level: SecurityLevel
    ) -> AttResult<Vec<u8>> {
        // Check if there's a read callback
        let read_callbacks = self.read_callbacks.read().unwrap();
        if let Some(callback) = read_callbacks.get(&handle) {
            return callback(handle);
        }
        
        // Otherwise, read directly from the attribute
        let attributes = self.attributes.read().unwrap();
        
        let attr = attributes.get(&handle)
            .ok_or(AttError::InvalidHandle(handle))?;
            
        let value = attr.read(security_level)?;
        
        Ok(value.to_vec())
    }
    
    /// Read a blob (partial value) by handle and offset
    pub fn read_blob_by_handle(
        &self,
        handle: u16,
        offset: u16,
        security_level: SecurityLevel
    ) -> AttResult<Vec<u8>> {
        // Get the full value
        let value = self.read_by_handle(handle, security_level)?;
        
        // Check if offset is valid
        if offset as usize > value.len() {
            return Err(AttError::InvalidOffset(offset));
        }
        
        // Return the partial value
        Ok(value[offset as usize..].to_vec())
    }
    
    /// Read multiple attribute values by handles
    pub fn read_multiple(
        &self,
        handles: &[u16],
        security_level: SecurityLevel
    ) -> AttResult<Vec<u8>> {
        let mut result = Vec::new();
        
        for &handle in handles {
            let value = self.read_by_handle(handle, security_level)?;
            result.extend_from_slice(&value);
        }
        
        Ok(result)
    }
    
    /// Write an attribute value by handle
    pub fn write_by_handle(
        &self,
        handle: u16,
        value: &[u8],
        security_level: SecurityLevel
    ) -> AttResult<()> {
        // Check if there's a write callback
        let write_callbacks = self.write_callbacks.read().unwrap();
        if let Some(callback) = write_callbacks.get(&handle) {
            return callback(handle, value);
        }
        
        // Otherwise, write directly to the attribute
        let mut attributes = self.attributes.write().unwrap();
        
        let attr = attributes.get_mut(&handle)
            .ok_or(AttError::InvalidHandle(handle))?;
            
        attr.write(value, security_level)
    }
    
    /// Get an attribute by handle
    pub fn get_attribute(&self, handle: u16) -> AttResult<Attribute> {
        let attributes = self.attributes.read().unwrap();
        
        attributes.get(&handle)
            .cloned()
            .ok_or(AttError::AttributeNotFound)
    }
    
    /// Get all attributes in a range
    pub fn get_attributes_in_range(
        &self,
        start_handle: u16,
        end_handle: u16
    ) -> AttResult<Vec<Attribute>> {
        let attributes = self.attributes.read().unwrap();
        let mut results = Vec::new();
        
        for (_, attr) in attributes.range(start_handle..=end_handle) {
            results.push(attr.clone());
        }
        
        Ok(results)
    }
    
    /// Check if an attribute exists
    pub fn has_attribute(&self, handle: u16) -> bool {
        let attributes = self.attributes.read().unwrap();
        attributes.contains_key(&handle)
    }
    
    /// Remove an attribute by handle
    pub fn remove_attribute(&self, handle: u16) -> AttResult<()> {
        let mut attributes = self.attributes.write().unwrap();
        
        if attributes.remove(&handle).is_none() {
            return Err(AttError::AttributeNotFound);
        }
        
        // Also remove any callbacks
        {
            let mut write_callbacks = self.write_callbacks.write().unwrap();
            write_callbacks.remove(&handle);
        }
        
        {
            let mut read_callbacks = self.read_callbacks.write().unwrap();
            read_callbacks.remove(&handle);
        }
        
        Ok(())
    }
    
    /// Clear all attributes
    pub fn clear(&self) {
        let mut attributes = self.attributes.write().unwrap();
        attributes.clear();
        
        let mut write_callbacks = self.write_callbacks.write().unwrap();
        write_callbacks.clear();
        
        let mut read_callbacks = self.read_callbacks.write().unwrap();
        read_callbacks.clear();
        
        *self.next_handle.write().unwrap() = ATT_HANDLE_MIN;
    }
    
    /// Get the handle range for a group by type
    pub fn get_group_handles(
        &self,
        start_handle: u16,
        end_handle: u16,
        group_type: &Uuid,
        security_level: SecurityLevel
    ) -> AttResult<Vec<(u16, u16, Vec<u8>)>> {
        let attributes = self.attributes.read().unwrap();
        let mut results = Vec::new();
        
        // Find all primary/secondary service declarations
        let mut service_handles = Vec::new();
        for (&handle, attr) in attributes.range(start_handle..=end_handle) {
            if attr.type_ == *group_type && attr.can_read(security_level) {
                service_handles.push(handle);
            }
        }
        
        // Sort service handles (should already be sorted, but just to be sure)
        service_handles.sort();
        
        // For each service, find its end handle
        for i in 0..service_handles.len() {
            let service_handle = service_handles[i];
            let service_attr = attributes.get(&service_handle).unwrap();
            
            // The end handle is either the handle before the next service or the end of range
            let end_handle = if i < service_handles.len() - 1 {
                service_handles[i + 1] - 1
            } else {
                end_handle
            };
            
            // Read the service value
            if let Ok(value) = service_attr.read(security_level) {
                results.push((service_handle, end_handle, value.to_vec()));
            }
        }
        
        Ok(results)
    }
    
    /// Find attributes by type in a range
    pub fn read_by_type(
        &self,
        start_handle: u16,
        end_handle: u16,
        attr_type: &Uuid,
        security_level: SecurityLevel
    ) -> AttResult<Vec<(u16, Vec<u8>)>> {
        let attributes = self.attributes.read().unwrap();
        let mut results = Vec::new();
        
        for (&handle, attr) in attributes.range(start_handle..=end_handle) {
            if attr.type_ == *attr_type && attr.can_read(security_level) {
                match attr.read(security_level) {
                    Ok(value) => {
                        results.push((handle, value.to_vec()));
                    },
                    Err(_) => {
                        // Skip attributes that can't be read
                    }
                }
            }
        }
        
        Ok(results)
    }
}