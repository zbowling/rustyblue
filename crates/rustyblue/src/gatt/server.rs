//! GATT Server implementation
//!
//! This module provides a server for GATT services, building on top of the ATT layer.

use std::sync::{Arc, RwLock};
use std::collections::{HashMap, BTreeMap};
use crate::att::{
    AttServer, AttributeDatabase, Attribute, AttPermissions, 
    SecurityLevel, AttError, AttResult,
    ATT_DEFAULT_MTU, PRIMARY_SERVICE_UUID, SECONDARY_SERVICE_UUID,
    CHARACTERISTIC_UUID, CLIENT_CHAR_CONFIG_UUID
};
use crate::gap::BdAddr;
use super::types::{Service, Characteristic, CharacteristicProperty, Uuid};
use std::io::{Cursor, Read};

/// GATT Server configuration
#[derive(Debug, Clone)]
pub struct GattServerConfig {
    /// Maximum MTU size
    pub max_mtu: u16,
    /// Default security level
    pub security_level: SecurityLevel,
}

impl Default for GattServerConfig {
    fn default() -> Self {
        Self {
            max_mtu: ATT_DEFAULT_MTU,
            security_level: SecurityLevel::None,
        }
    }
}

/// GATT characteristic descriptor
#[derive(Debug, Clone)]
pub struct Descriptor {
    /// Descriptor UUID
    pub uuid: Uuid,
    /// Descriptor handle
    pub handle: u16,
    /// Descriptor value
    pub value: Vec<u8>,
    /// Descriptor permissions
    pub permissions: AttPermissions,
}

/// GATT characteristic with its descriptors
#[derive(Debug)]
pub struct GattCharacteristic {
    /// Characteristic declaration handle
    pub declaration_handle: u16,
    /// Characteristic value handle
    pub value_handle: u16,
    /// Characteristic UUID
    pub uuid: Uuid,
    /// Characteristic properties
    pub properties: CharacteristicProperty,
    /// Characteristic descriptors
    pub descriptors: Vec<Descriptor>,
    /// Characteristic value
    pub value: RwLock<Vec<u8>>,
    /// Characteristic permissions
    pub permissions: AttPermissions,
}

/// A GATT service with characteristics
#[derive(Debug, Clone)]
pub struct GattService {
    /// Service declaration handle
    pub handle: u16,
    /// Service UUID
    pub uuid: Uuid,
    /// Is this a primary service?
    pub is_primary: bool,
    /// Service characteristics
    pub characteristics: Vec<GattCharacteristic>,
    /// Service end handle
    pub end_handle: u16,
}

/// A GATT server
pub struct GattServer {
    /// Server configuration
    config: RwLock<GattServerConfig>,
    /// ATT server
    att_server: Arc<AttServer>,
    /// Attribute database
    database: Arc<AttributeDatabase>,
    /// Services by handle
    services: RwLock<BTreeMap<u16, GattService>>,
    /// Characteristics by value handle
    characteristics: RwLock<HashMap<u16, GattCharacteristic>>,
    /// Client notifications enabled flags (handle -> client address)
    notifications: RwLock<HashMap<u16, Vec<BdAddr>>>,
    /// Client indications enabled flags (handle -> client address)
    indications: RwLock<HashMap<u16, Vec<BdAddr>>>,
}

impl GattServer {
    /// Create a new GATT server
    pub fn new(att_server: Arc<AttServer>, database: Arc<AttributeDatabase>) -> Self {
        Self {
            config: RwLock::new(GattServerConfig::default()),
            att_server,
            database,
            services: RwLock::new(BTreeMap::new()),
            characteristics: RwLock::new(HashMap::new()),
            notifications: RwLock::new(HashMap::new()),
            indications: RwLock::new(HashMap::new()),
        }
    }
    
    /// Set GATT server configuration
    pub fn set_config(&self, config: GattServerConfig) {
        let mut server_config = self.config.write().unwrap();
        *server_config = config.clone();
        
        // Also update ATT server configuration
        self.att_server.set_config(crate::att::AttServerConfig {
            mtu: config.max_mtu,
            security_level: config.security_level,
        });
    }
    
    /// Get GATT server configuration
    pub fn config(&self) -> GattServerConfig {
        self.config.read().unwrap().clone()
    }
    
    /// Start the GATT server
    pub fn start(&self) -> AttResult<()> {
        // Start the ATT server
        self.att_server.start()
    }
    
    /// Stop the GATT server
    pub fn stop(&self) -> AttResult<()> {
        // Stop the ATT server
        self.att_server.stop()
    }
    
    /// Add a service to the GATT server
    pub fn add_service(&self, uuid: Uuid, is_primary: bool) -> AttResult<u16> {
        // Create service declaration attribute
        let service_type = if is_primary {
            PRIMARY_SERVICE_UUID
        } else {
            SECONDARY_SERVICE_UUID
        };
        
        let mut value = Vec::new();
        if let Some(uuid16) = uuid.as_u16() {
            value.extend_from_slice(&uuid16.to_le_bytes());
        } else {
            value.extend_from_slice(&uuid.as_bytes());
        }
        
        let handle = self.database.add_attribute_with_next_handle(
            Uuid::from_u16(service_type),
            value,
            AttPermissions::read_only(),
        )?;
        
        // Create new service (end handle is tentative)
        let service = GattService {
            handle,
            uuid,
            is_primary,
            characteristics: Vec::new(),
            end_handle: handle, // This will be updated as characteristics are added
        };
        
        // Store service
        let mut services = self.services.write().unwrap();
        services.insert(handle, service);
        
        Ok(handle)
    }
    
    /// Add a characteristic to a service
    pub fn add_characteristic(
        &self,
        service_handle: u16,
        uuid: Uuid,
        properties: CharacteristicProperty,
        permissions: AttPermissions,
        initial_value: Vec<u8>
    ) -> AttResult<u16> {
        // Find the service
        let mut services = self.services.write().unwrap();
        let service = services.get_mut(&service_handle)
            .ok_or(AttError::AttributeNotFound)?;
        
        // Create characteristic declaration attribute
        let mut declaration_value = Vec::new();
        declaration_value.push(properties.0);
        
        // We'll set the value handle later, first put a placeholder
        declaration_value.extend_from_slice(&[0, 0]);
        
        // Add the UUID
        if let Some(uuid16) = uuid.as_u16() {
            declaration_value.extend_from_slice(&uuid16.to_le_bytes());
        } else {
            declaration_value.extend_from_slice(&uuid.as_bytes());
        }
        
        // Add characteristic declaration attribute to database
        let declaration_handle = self.database.add_attribute_with_next_handle(
            Uuid::from_u16(CHARACTERISTIC_UUID),
            declaration_value.clone(),
            AttPermissions::read_only(),
        )?;
        
        // Now add the characteristic value attribute
        let value_handle = self.database.add_attribute_with_next_handle(
            uuid.clone(),
            initial_value.clone(),
            permissions,
        )?;
        
        // Update the declaration value with the correct value handle
        let declaration_bytes = value_handle.to_le_bytes();
        declaration_value[1] = declaration_bytes[0];
        declaration_value[2] = declaration_bytes[1];
        
        // Update the declaration attribute
        let decl_attr = Attribute::new(
            declaration_handle,
            Uuid::from_u16(CHARACTERISTIC_UUID),
            declaration_value,
            AttPermissions::read_only(),
        );
        self.database.add_attribute(decl_attr)?;
        
        // Create a characteristic object
        let characteristic = GattCharacteristic {
            declaration_handle,
            value_handle,
            uuid,
            properties,
            descriptors: Vec::new(),
            value: RwLock::new(initial_value),
            permissions,
        };
        
        // Store characteristic
        let mut characteristics = self.characteristics.write().unwrap();
        characteristics.insert(value_handle, characteristic);
        
        // Add to service
        let characteristic_ref = characteristics.get(&value_handle).unwrap();
        service.characteristics.push(characteristic_ref.clone());
        
        // Update service end handle
        service.end_handle = value_handle;
        
        Ok(value_handle)
    }
    
    /// Add a descriptor to a characteristic
    pub fn add_descriptor(
        &self,
        characteristic_value_handle: u16,
        uuid: Uuid,
        permissions: AttPermissions,
        initial_value: Vec<u8>
    ) -> AttResult<u16> {
        // Find the characteristic
        let mut characteristics = self.characteristics.write().unwrap();
        let characteristic = characteristics.get_mut(&characteristic_value_handle)
            .ok_or(AttError::AttributeNotFound)?;
        
        // Add descriptor attribute to database
        let handle = self.database.add_attribute_with_next_handle(
            uuid.clone(),
            initial_value.clone(),
            permissions,
        )?;
        
        // Create descriptor object
        let descriptor = Descriptor {
            uuid,
            handle,
            value: initial_value,
            permissions,
        };
        
        // Add to characteristic
        characteristic.descriptors.push(descriptor);
        
        // Find the service and update its end handle
        let mut services = self.services.write().unwrap();
        for service in services.values_mut() {
            for char in &service.characteristics {
                if char.value_handle == characteristic_value_handle {
                    service.end_handle = handle;
                    break;
                }
            }
        }
        
        Ok(handle)
    }
    
    /// Add the standard Client Characteristic Configuration descriptor to a characteristic
    pub fn add_cccd(&self, characteristic_value_handle: u16) -> AttResult<u16> {
        // Find the characteristic
        let characteristics = self.characteristics.read().unwrap();
        let characteristic = characteristics.get(&characteristic_value_handle)
            .ok_or(AttError::AttributeNotFound)?;
        
        // Check properties
        if !characteristic.properties.can_notify() && !characteristic.properties.can_indicate() {
            return Err(AttError::InvalidParameter(
                "Characteristic does not support notifications or indications".into()
            ));
        }
        
        // Add CCCD
        let handle = self.add_descriptor(
            characteristic_value_handle,
            Uuid::from_u16(CLIENT_CHAR_CONFIG_UUID),
            AttPermissions::read_write(),
            vec![0, 0], // Notifications and indications disabled by default
        )?;
        
        // Initialize notification/indication mappings
        {
            let mut notifications = self.notifications.write().unwrap();
            notifications.insert(characteristic_value_handle, Vec::new());
        }
        
        {
            let mut indications = self.indications.write().unwrap();
            indications.insert(characteristic_value_handle, Vec::new());
        }
        
        // Register callback for CCCD writes
        let server = Arc::new(self.clone());
        let database = self.database.clone();
        
        self.database.register_write_callback(
            handle,
            Arc::new(move |handle, value| {
                if value.len() != 2 {
                    return Err(AttError::InvalidAttributeValueLength);
                }
                
                // Update in-memory value
                let attr = database.get_attribute(handle)?;
                
                // Process CCCD value
                server.process_cccd_write(characteristic_value_handle, value)?;
                
                Ok(())
            })
        )?;
        
        Ok(handle)
    }
    
    /// Process a write to a Client Characteristic Configuration descriptor
    fn process_cccd_write(&self, char_handle: u16, value: &[u8]) -> AttResult<()> {
        if value.len() != 2 {
            return Err(AttError::InvalidAttributeValueLength);
        }
        
        let flags = u16::from_le_bytes([value[0], value[1]]);
        let notifications_enabled = (flags & 0x0001) != 0;
        let indications_enabled = (flags & 0x0002) != 0;
        
        // Currently we'd need the client address to properly track this
        // For now, just update the local state
        
        Ok(())
    }
    
    /// Update a characteristic value and notify/indicate clients if configured
    pub fn update_characteristic(
        &self,
        handle: u16,
        value: &[u8],
        notify: bool,
        indicate: bool
    ) -> AttResult<()> {
        // Find the characteristic
        let characteristics = self.characteristics.read().unwrap();
        let characteristic = characteristics.get(&handle)
            .ok_or(AttError::AttributeNotFound)?;
        
        // Update the value
        {
            let mut char_value = characteristic.value.write().unwrap();
            *char_value = value.to_vec();
        }
        
        // Update the attribute database
        self.database.write_by_handle(handle, value, SecurityLevel::None)?;
        
        // Send notifications if requested
        if notify && characteristic.properties.can_notify() {
            let notifications = self.notifications.read().unwrap();
            if let Some(clients) = notifications.get(&handle) {
                for client in clients {
                    // Skip errors, client might be disconnected
                    let _ = self.att_server.send_notification(*client, handle, value);
                }
            }
        }
        
        // Send indications if requested
        if indicate && characteristic.properties.can_indicate() {
            let indications = self.indications.read().unwrap();
            if let Some(clients) = indications.get(&handle) {
                for client in clients {
                    // Skip errors, client might be disconnected
                    let _ = self.att_server.send_indication(*client, handle, value);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get a characteristic value by handle
    pub fn get_characteristic_value(&self, handle: u16) -> AttResult<Vec<u8>> {
        // Find the characteristic
        let characteristics = self.characteristics.read().unwrap();
        let characteristic = characteristics.get(&handle)
            .ok_or(AttError::AttributeNotFound)?;
        
        // Get the value
        let char_value = characteristic.value.read().unwrap();
        
        Ok(char_value.clone())
    }
    
    /// Get all services
    pub fn get_services(&self) -> Vec<Service> {
        let services = self.services.read().unwrap();
        
        services.values()
            .map(|svc| Service {
                uuid: svc.uuid.clone(),
                is_primary: svc.is_primary,
                start_handle: svc.handle,
                end_handle: svc.end_handle,
            })
            .collect()
    }
    
    /// Get characteristics for a service
    pub fn get_characteristics(&self, service_handle: u16) -> AttResult<Vec<Characteristic>> {
        // Find the service
        let services = self.services.read().unwrap();
        let service = services.get(&service_handle)
            .ok_or(AttError::AttributeNotFound)?;
        
        // Convert GattCharacteristic to Characteristic
        let characteristics = service.characteristics.iter()
            .map(|gatt_char| Characteristic {
                uuid: gatt_char.uuid.clone(),
                declaration_handle: gatt_char.declaration_handle,
                value_handle: gatt_char.value_handle,
                properties: gatt_char.properties,
            })
            .collect();
        
        Ok(characteristics)
    }
    
    /// Register a client (called when a client connects)
    pub fn register_client(&self, addr: BdAddr, security_level: SecurityLevel) -> AttResult<()> {
        // Nothing to do here yet, but would be used for security and connection tracking
        Ok(())
    }
    
    /// Unregister a client (called when a client disconnects)
    pub fn unregister_client(&self, addr: BdAddr) -> AttResult<()> {
        // Clean up any notification/indication registrations
        {
            let mut notifications = self.notifications.write().unwrap();
            for clients in notifications.values_mut() {
                clients.retain(|client| *client != addr);
            }
        }
        
        {
            let mut indications = self.indications.write().unwrap();
            for clients in indications.values_mut() {
                clients.retain(|client| *client != addr);
            }
        }
        
        Ok(())
    }
}

impl Clone for GattServer {
    fn clone(&self) -> Self {
        Self {
            config: RwLock::new(self.config.read().unwrap().clone()),
            att_server: self.att_server.clone(),
            database: self.database.clone(),
            services: RwLock::new(self.services.read().unwrap().clone()),
            characteristics: RwLock::new(self.characteristics.read().unwrap().clone()),
            notifications: RwLock::new(self.notifications.read().unwrap().clone()),
            indications: RwLock::new(self.indications.read().unwrap().clone()),
        }
    }
}