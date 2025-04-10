//! Security Manager Protocol manager implementation
//!
//! This module provides the main interface for the SMP module, handling
//! pairing, encryption, and key management.

use super::types::*;
use super::constants::*;
use super::keys::*;
use super::pairing::*;
use super::crypto::*;
use crate::gap::BdAddr;
use crate::hci::{HciSocket, HciCommand, HciEvent};
use crate::l2cap::{L2capManager, L2capChannel, L2capResult, L2capError, SecurityLevel as L2capSecurityLevel}; // Import L2cap SecurityLevel
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Type for SMP event callback
pub type SmpEventCallback = Arc<Mutex<dyn FnMut(SmpEvent) -> SmpResult<()> + Send + Sync>>;

/// Type for passkey callback
pub type PasskeyCallback = Arc<Mutex<dyn FnMut(BdAddr) -> SmpResult<u32> + Send + Sync>>;

/// Type for comparison callback
pub type ComparisonCallback = Arc<Mutex<dyn FnMut(BdAddr, u32) -> SmpResult<bool> + Send + Sync>>;

/// Security Manager Protocol manager
pub struct SmpManager {
    /// Local device features
    features: PairingFeatures,
    
    /// Active pairing processes
    pairing_processes: RwLock<HashMap<BdAddr, PairingProcess>>,
    
    /// Security levels of connected devices
    security_levels: RwLock<HashMap<BdAddr, SecurityLevel>>,
    
    /// Event callback
    event_callback: Mutex<Option<SmpEventCallback>>,
    
    /// Passkey callback
    passkey_callback: Mutex<Option<PasskeyCallback>>,
    
    /// Comparison callback
    comparison_callback: Mutex<Option<ComparisonCallback>>,
    
    /// Key store
    key_store: RwLock<KeyStoreHandle>,
    
    /// L2CAP manager for sending SMP messages
    l2cap_manager: Arc<L2capManager>,
    
    /// HCI socket for encryption commands
    hci_socket: Arc<HciSocket>,
    
    /// Local OOB data
    local_oob_data: RwLock<Option<OobData>>,
}

impl SmpManager {
    /// Create a new SMP manager
    pub fn new(
        l2cap_manager: Arc<L2capManager>,
        hci_socket: Arc<HciSocket>,
        key_store: KeyStoreHandle,
    ) -> Self {
        // Default features
        let features = PairingFeatures {
            io_capability: IoCapability::NoInputNoOutput,
            oob_data_present: false,
            auth_req: AuthRequirements::default(),
            max_key_size: SMP_MAX_ENCRYPTION_KEY_SIZE,
            initiator_key_dist: KeyDistribution::all(),
            responder_key_dist: KeyDistribution::all(),
        };
        
        Self {
            features,
            pairing_processes: RwLock::new(HashMap::new()),
            security_levels: RwLock::new(HashMap::new()),
            event_callback: Mutex::new(None),
            passkey_callback: Mutex::new(None),
            comparison_callback: Mutex::new(None),
            key_store: RwLock::new(key_store),
            l2cap_manager,
            hci_socket,
            local_oob_data: RwLock::new(None),
        }
    }
    
    /// Set the event callback
    pub fn set_event_callback<F>(&self, callback: F)
    where
        F: FnMut(SmpEvent) -> SmpResult<()> + Send + Sync + 'static,
    {
        let mut event_callback = self.event_callback.lock().unwrap();
        *event_callback = Some(Arc::new(Mutex::new(callback)));
    }
    
    /// Set the passkey callback
    pub fn set_passkey_callback<F>(&self, callback: F)
    where
        F: FnMut(BdAddr) -> SmpResult<u32> + Send + Sync + 'static,
    {
        let mut passkey_callback = self.passkey_callback.lock().unwrap();
        *passkey_callback = Some(Arc::new(Mutex::new(callback)));
    }
    
    /// Set the comparison callback
    pub fn set_comparison_callback<F>(&self, callback: F)
    where
        F: FnMut(BdAddr, u32) -> SmpResult<bool> + Send + Sync + 'static,
    {
        let mut comparison_callback = self.comparison_callback.lock().unwrap();
        *comparison_callback = Some(Arc::new(Mutex::new(callback)));
    }
    
    /// Set local device features
    pub fn set_features(&mut self, features: PairingFeatures) {
        self.features = features;
    }
    
    /// Get local device features
    pub fn features(&self) -> PairingFeatures {
        self.features.clone()
    }
    
    /// Set the local IO capability
    pub fn set_io_capability(&mut self, io_capability: IoCapability) {
        self.features.io_capability = io_capability;
    }
    
    /// Set whether OOB data is present
    pub fn set_oob_data_present(&mut self, present: bool) {
        self.features.oob_data_present = present;
    }
    
    /// Set authentication requirements
    pub fn set_auth_requirements(&mut self, auth_req: AuthRequirements) {
        self.features.auth_req = auth_req;
    }
    
    /// Generate local OOB data
    pub fn generate_oob_data(&self) -> SmpResult<OobData> {
        let r = generate_random_128();
        
        // In a real implementation, we would calculate c properly
        // For now, we'll just use zeros
        let c = [0u8; 16];
        
        let oob_data = OobData { r, c };
        
        // Store locally
        let mut local_oob_data = self.local_oob_data.write().unwrap();
        *local_oob_data = Some(oob_data.clone());
        
        Ok(oob_data)
    }
    
    /// Initiate pairing with a remote device
    pub fn initiate_pairing(&self, remote_addr: BdAddr) -> SmpResult<()> {
        // Check if we're already pairing with this device
        {
            let pairing_processes = self.pairing_processes.read().unwrap();
            if pairing_processes.contains_key(&remote_addr) {
                return Err(SmpError::InvalidState);
            }
        }
        
        // Create a new pairing process
        let mut process = PairingProcess::new_initiator(remote_addr, self.features.clone());
        
        // Prepare pairing request
        let pairing_req = PairingRequest::from_features(&self.features);
        
        // Move to waiting for response state
        process.state = PairingState::WaitingPairingResponse;
        
        // Store the process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        // Send pairing request
        self.send_pairing_request(remote_addr, pairing_req)?;
        
        Ok(())
    }
    
    /// Handle a security request
    pub fn handle_security_request(&self, remote_addr: BdAddr, auth_req: u8) -> SmpResult<()> {
        // Parse auth requirements
        let auth_requirements = AuthRequirements::from_u8(auth_req);
        
        // Notify the application
        self.notify_event(SmpEvent::PairingRequest(remote_addr, PairingFeatures {
            io_capability: IoCapability::NoInputNoOutput,
            oob_data_present: false,
            auth_req: auth_requirements,
            max_key_size: SMP_MAX_ENCRYPTION_KEY_SIZE,
            initiator_key_dist: KeyDistribution::none(),
            responder_key_dist: KeyDistribution::none(),
        }))?;
        
        // Initiate pairing if auto-pairing is enabled
        // For now, we'll always initiate pairing in response
        self.initiate_pairing(remote_addr)
    }
    
    /// Check if a device is paired
    pub fn is_paired(&self, remote_addr: &BdAddr) -> SmpResult<bool> {
        let key_store = self.key_store.read().unwrap();
        match key_store.load_keys(remote_addr)? {
            Some(keys) => Ok(keys.has_keys()),
            None => Ok(false),
        }
    }
    
    /// Get the security level for a device
    pub fn security_level(&self, remote_addr: &BdAddr) -> SmpResult<SecurityLevel> {
        // Check current connections first
        {
            let security_levels = self.security_levels.read().unwrap();
            if let Some(level) = security_levels.get(remote_addr) {
                return Ok(*level);
            }
        }
        
        // Check stored keys
        let key_store = self.key_store.read().unwrap();
        match key_store.load_keys(remote_addr)? {
            Some(keys) => Ok(keys.security_level()),
            None => Ok(SecurityLevel::None),
        }
    }
    
    /// Get all paired devices
    pub fn paired_devices(&self) -> SmpResult<Vec<BdAddr>> {
        let key_store = self.key_store.read().unwrap();
        key_store.get_paired_devices()
    }
    
    /// Remove pairing (unpair device)
    pub fn remove_pairing(&self, remote_addr: &BdAddr) -> SmpResult<()> {
        let mut key_store = self.key_store.write().unwrap();
        key_store.delete_keys(remote_addr)
    }
    
    /// Handle an incoming SMP packet
    pub fn handle_smp_packet(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        if data.is_empty() {
            return Err(SmpError::InvalidParameter("Empty SMP packet".into()));
        }
        
        // Extract command code
        let command_code = data[0];
        
        match command_code {
            SMP_PAIRING_REQUEST => self.handle_pairing_request(remote_addr, data),
            SMP_PAIRING_RESPONSE => self.handle_pairing_response(remote_addr, data),
            SMP_PAIRING_CONFIRM => self.handle_pairing_confirm(remote_addr, data),
            SMP_PAIRING_RANDOM => self.handle_pairing_random(remote_addr, data),
            SMP_PAIRING_FAILED => self.handle_pairing_failed(remote_addr, data),
            SMP_ENCRYPTION_INFORMATION => self.handle_encryption_information(remote_addr, data),
            SMP_MASTER_IDENTIFICATION => self.handle_master_identification(remote_addr, data),
            SMP_IDENTITY_INFORMATION => self.handle_identity_information(remote_addr, data),
            SMP_IDENTITY_ADDRESS_INFORMATION => self.handle_identity_address_information(remote_addr, data),
            SMP_SIGNING_INFORMATION => self.handle_signing_information(remote_addr, data),
            SMP_SECURITY_REQUEST => self.handle_security_request_packet(remote_addr, data),
            SMP_PAIRING_PUBLIC_KEY => self.handle_pairing_public_key(remote_addr, data),
            SMP_PAIRING_DHK_CHECK => self.handle_pairing_dhkey_check(remote_addr, data),
            SMP_PAIRING_KEYPRESS_NOTIFICATION => self.handle_keypress_notification(remote_addr, data),
            _ => Err(SmpError::CommandNotSupported),
        }
    }
    
    /// Handle an HCI event
    pub fn handle_hci_event(&self, event: &HciEvent) -> SmpResult<()> {
        // Handle encryption changed event
        // Handle encryption key refresh event
        // Handle other relevant HCI events
        
        Ok(())
    }
    
    /// Process timeouts
    pub fn process_timeouts(&self) -> SmpResult<()> {
        let mut to_remove = Vec::new();
        
        // Check for timed out pairing processes
        {
            let pairing_processes = self.pairing_processes.read().unwrap();
            for (addr, process) in pairing_processes.iter() {
                if process.has_timed_out(Duration::from_millis(SMP_TIMEOUT_GENERAL)) {
                    to_remove.push(*addr);
                }
            }
        }
        
        // Remove timed out processes
        if !to_remove.is_empty() {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            for addr in to_remove {
                pairing_processes.remove(&addr);
                
                // Notify application
                self.notify_event(SmpEvent::PairingFailed(addr, SmpError::Timeout))?;
            }
        }
        
        Ok(())
    }
    
    // Internal methods for handling SMP messages
    
    /// Handle a pairing request
    fn handle_pairing_request(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the pairing request
        let pairing_req = PairingRequest::parse(data)?;
        let features = pairing_req.to_features();
        
        // Make sure we're not already pairing
        {
            let pairing_processes = self.pairing_processes.read().unwrap();
            if pairing_processes.contains_key(&remote_addr) {
                return Err(SmpError::InvalidState);
            }
        }
        
        // Notify the application
        self.notify_event(SmpEvent::PairingRequest(remote_addr, features.clone()))?;
        
        // Create a new pairing process as responder
        let mut process = PairingProcess::new_responder(remote_addr, self.features.clone());
        
        // Store the remote features
        process.remote_features = Some(features);
        
        // Determine pairing method
        process.secure_connections = self.features.auth_req.secure_connections && 
                                     process.remote_features.as_ref().unwrap().auth_req.secure_connections;
        process.method = Some(process.determine_pairing_method()?);
        
        // Prepare pairing response
        let pairing_rsp = PairingRequest::from_features(&self.features);
        
        // Store the process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        // Send pairing response
        self.send_pairing_response(remote_addr, pairing_rsp)?;
        
        // Update state
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            if let Some(process) = pairing_processes.get_mut(&remote_addr) {
                if process.secure_connections {
                    // Generate keypair for Secure Connections
                    let (private_key, public_key) = generate_keypair();
                    process.local_private_key = Some(private_key);
                    process.local_public_key = Some(public_key);
                    
                    // Wait for public key
                    process.state = PairingState::WaitingPublicKey;
                } else {
                    // For legacy pairing, generate TK, random and confirm
                    match process.method {
                        Some(PairingMethod::JustWorks) => {
                            // TK is all zeros for Just Works
                            process.tk = Some([0u8; 16]);
                        },
                        Some(PairingMethod::PasskeyEntry) => {
                            // Handle passkey entry based on IO capabilities
                            // Either display or request a passkey
                            if self.features.io_capability == IoCapability::DisplayOnly || 
                               self.features.io_capability == IoCapability::DisplayYesNo {
                                // Generate and display passkey
                                let passkey = generate_passkey();
                                
                                // Create TK from passkey
                                let mut tk = [0u8; 16];
                                tk[0..4].copy_from_slice(&passkey.to_le_bytes());
                                
                                process.tk = Some(tk);
                                process.passkey = Some(passkey);
                                
                                // Notify application to display passkey
                                self.notify_event(SmpEvent::DisplayPasskey(remote_addr, passkey))?;
                            } else {
                                // Will request passkey later
                            }
                        },
                        Some(PairingMethod::OutOfBand) => {
                            // Get OOB data
                            let local_oob_data = self.local_oob_data.read().unwrap();
                            if let Some(oob_data) = local_oob_data.as_ref() {
                                process.tk = Some(oob_data.r);
                            } else {
                                // No OOB data available
                                return self.send_pairing_failed(remote_addr, SMP_REASON_OOB_NOT_AVAILABLE);
                            }
                        },
                        _ => {
                            // Invalid method for legacy pairing
                            return self.send_pairing_failed(remote_addr, SMP_REASON_UNSPECIFIED_REASON);
                        }
                    }
                    
                    // Generate random value
                    process.local_random = Some(generate_random_128());
                    
                    // Wait for pairing confirm
                    process.state = PairingState::WaitingPairingConfirm;
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle a pairing response
    fn handle_pairing_response(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the pairing response
        let pairing_rsp = PairingRequest::parse(data)?;
        let features = pairing_rsp.to_features();
        
        // Get the pairing process
        let mut process = {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr).ok_or(SmpError::InvalidState)?
        };
        
        // Make sure we're in the correct state
        if process.state != PairingState::WaitingPairingResponse {
            // Put the process back
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
            
            return Err(SmpError::InvalidState);
        }
        
        // Store the remote features
        process.remote_features = Some(features.clone());
        
        // Notify the application
        self.notify_event(SmpEvent::PairingResponse(remote_addr, features))?;
        
        // Determine pairing method
        process.secure_connections = self.features.auth_req.secure_connections && 
                                     process.remote_features.as_ref().unwrap().auth_req.secure_connections;
        process.method = Some(process.determine_pairing_method()?);
        
        // Process based on pairing method
        if process.secure_connections {
            // Generate keypair for Secure Connections
            let (private_key, public_key) = generate_keypair();
            process.local_private_key = Some(private_key);
            process.local_public_key = Some(public_key);
            
            // Send public key
            let public_key_packet = PairingPublicKey::from_bytes(&public_key);
            self.send_pairing_public_key(remote_addr, public_key_packet)?;
            
            // Update state
            process.state = PairingState::WaitingPublicKey;
        } else {
            // For legacy pairing, generate TK, random and confirm
            match process.method {
                Some(PairingMethod::JustWorks) => {
                    // TK is all zeros for Just Works
                    process.tk = Some([0u8; 16]);
                },
                Some(PairingMethod::PasskeyEntry) => {
                    // Handle passkey entry based on IO capabilities
                    // Either display or request a passkey
                    if self.features.io_capability == IoCapability::DisplayOnly || 
                       self.features.io_capability == IoCapability::DisplayYesNo {
                        // Generate and display passkey
                        let passkey = generate_passkey();
                        
                        // Create TK from passkey
                        let mut tk = [0u8; 16];
                        tk[0..4].copy_from_slice(&passkey.to_le_bytes());
                        
                        process.tk = Some(tk);
                        process.passkey = Some(passkey);
                        
                        // Notify application to display passkey
                        self.notify_event(SmpEvent::DisplayPasskey(remote_addr, passkey))?;
                    } else {
                        // Request passkey from user
                        self.notify_event(SmpEvent::PasskeyRequest(remote_addr))?;
                        
                        // Will be set when the user provides the passkey
                    }
                },
                Some(PairingMethod::OutOfBand) => {
                    // Get OOB data
                    let local_oob_data = self.local_oob_data.read().unwrap();
                    if let Some(oob_data) = local_oob_data.as_ref() {
                        process.tk = Some(oob_data.r);
                    } else {
                        // No OOB data available
                        return self.send_pairing_failed(remote_addr, SMP_REASON_OOB_NOT_AVAILABLE);
                    }
                },
                _ => {
                    // Invalid method for legacy pairing
                    return self.send_pairing_failed(remote_addr, SMP_REASON_UNSPECIFIED_REASON);
                }
            }
            
            // Generate random value
            process.local_random = Some(generate_random_128());
            
            // Calculate confirm value
            if let (Some(tk), Some(local_random)) = (&process.tk, &process.local_random) {
                // Get preq and pres
                let preq = PairingRequest::from_features(&self.features).serialize(true);
                let pres = data.to_vec();
                
                // For simplicity, assume we're always the initiator in this example
                // In a real implementation, we would track which side initiated
                let init_addr_type = 0; // Public address
                let init_addr = [0u8; 6]; // Local address
                let resp_addr_type = 0; // Public address
                let resp_addr = [0u8; 6]; // Remote address
                
                let confirm_value = c1(
                    tk,
                    local_random,
                    &preq,
                    &pres,
                    init_addr_type,
                    &init_addr,
                    resp_addr_type,
                    &resp_addr,
                );
                
                process.local_confirm = Some(confirm_value);
                
                // Send pairing confirm
                let confirm = PairingConfirm::new(confirm_value);
                self.send_pairing_confirm(remote_addr, confirm)?;
                
                // Update state
                process.state = PairingState::WaitingPairingConfirm;
            } else {
                // Missing TK or random
                return self.send_pairing_failed(remote_addr, SMP_REASON_UNSPECIFIED_REASON);
            }
        }
        
        // Store the updated process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        Ok(())
    }
    
    /// Handle a pairing confirm
    fn handle_pairing_confirm(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the pairing confirm
        let pairing_confirm = PairingConfirm::parse(data)?;
        
        // Get the pairing process
        let mut process = {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr).ok_or(SmpError::InvalidState)?
        };
        
        // Store the remote confirm value
        process.remote_confirm = Some(pairing_confirm.confirm_value);
        
        // Handle based on role
        if process.role == PairingRole::Initiator {
            // As initiator, we send our random value
            if let Some(local_random) = &process.local_random {
                let random = PairingRandom::new(*local_random);
                self.send_pairing_random(remote_addr, random)?;
                
                // Update state
                process.state = PairingState::WaitingPairingRandom;
            } else {
                // Missing random
                return self.send_pairing_failed(remote_addr, SMP_REASON_UNSPECIFIED_REASON);
            }
        } else {
            // As responder, we calculate our confirm value if we haven't already
            if process.local_confirm.is_none() && process.tk.is_some() && process.local_random.is_some() {
                // Get preq and pres
                if let Some(remote_features) = &process.remote_features {
                    let preq = PairingRequest::from_features(remote_features).serialize(true);
                    let pres = PairingRequest::from_features(&self.features).serialize(false);
                    
                    // For simplicity, assume the remote is always the initiator in this example
                    let init_addr_type = 0; // Public address
                    let init_addr = [0u8; 6]; // Remote address
                    let resp_addr_type = 0; // Public address
                    let resp_addr = [0u8; 6]; // Local address
                    
                    let confirm_value = c1(
                        process.tk.as_ref().unwrap(),
                        process.local_random.as_ref().unwrap(),
                        &preq,
                        &pres,
                        init_addr_type,
                        &init_addr,
                        resp_addr_type,
                        &resp_addr,
                    );
                    
                    process.local_confirm = Some(confirm_value);
                }
            }
            
            // Send our confirm value
            if let Some(local_confirm) = &process.local_confirm {
                let confirm = PairingConfirm::new(*local_confirm);
                self.send_pairing_confirm(remote_addr, confirm)?;
                
                // Update state
                process.state = PairingState::WaitingPairingRandom;
            } else {
                // Missing confirm
                return self.send_pairing_failed(remote_addr, SMP_REASON_UNSPECIFIED_REASON);
            }
        }
        
        // Store the updated process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        Ok(())
    }
    
    /// Handle a pairing random
    fn handle_pairing_random(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the pairing random
        let pairing_random = PairingRandom::parse(data)?;
        
        // Get the pairing process
        let mut process = {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr).ok_or(SmpError::InvalidState)?
        };
        
        // Store the remote random value
        process.remote_random = Some(pairing_random.random_value);
        
        // For legacy pairing, verify the confirm value
        if !process.secure_connections {
            if let (Some(tk), Some(remote_random), Some(remote_confirm)) = 
                (&process.tk, &process.remote_random, &process.remote_confirm) {
                
                // Get preq and pres
                if let Some(remote_features) = &process.remote_features {
                    let preq = if process.role == PairingRole::Initiator {
                        PairingRequest::from_features(&self.features).serialize(true)
                    } else {
                        PairingRequest::from_features(remote_features).serialize(true)
                    };
                    
                    let pres = if process.role == PairingRole::Initiator {
                        PairingRequest::from_features(remote_features).serialize(false)
                    } else {
                        PairingRequest::from_features(&self.features).serialize(false)
                    };
                    
                    // Set addresses based on role
                    let (init_addr_type, init_addr, resp_addr_type, resp_addr) = 
                    if process.role == PairingRole::Initiator {
                        (0, [0u8; 6], 0, [0u8; 6]) // Local is initiator, remote is responder
                    } else {
                        (0, [0u8; 6], 0, [0u8; 6]) // Remote is initiator, local is responder
                    };
                    
                    // Calculate expected confirm value
                    let expected_confirm = c1(
                        tk,
                        remote_random,
                        &preq,
                        &pres,
                        init_addr_type,
                        &init_addr,
                        resp_addr_type,
                        &resp_addr,
                    );
                    
                    // Verify the confirm value
                    if expected_confirm != *remote_confirm {
                        // Confirm value doesn't match
                        return self.send_pairing_failed(remote_addr, SMP_REASON_CONFIRM_VALUE_FAILED);
                    }
                }
            }
            
            // Handle based on role
            if process.role == PairingRole::Responder {
                // As responder, we send our random
                if let Some(local_random) = &process.local_random {
                    let random = PairingRandom::new(*local_random);
                    self.send_pairing_random(remote_addr, random)?;
                } else {
                    // Missing random
                    return self.send_pairing_failed(remote_addr, SMP_REASON_UNSPECIFIED_REASON);
                }
            }
            
            // Calculate STK for legacy pairing
            if let (Some(tk), Some(local_random), Some(remote_random)) = 
                (&process.tk, &process.local_random, &process.remote_random) {
                
                // Calculate STK
                let stk = if process.role == PairingRole::Initiator {
                    s1(tk, local_random, remote_random)
                } else {
                    s1(tk, remote_random, local_random)
                };
                
                // Store the LTK
                process.ltk = Some(stk);
                
                // Encrypt the link using STK
                // In a real implementation, this would use HciCommand::EncryptionStart
                
                // Move to key distribution phase
                process.state = PairingState::WaitingKeyDistribution;
            }
        } else {
            // For Secure Connections, handle based on method
            // This is a placeholder for SC random handling
        }
        
        // Store the updated process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        Ok(())
    }
    
    /// Handle a pairing failed
    fn handle_pairing_failed(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the pairing failed
        let pairing_failed = PairingFailed::parse(data)?;
        
        // Remove the pairing process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr);
        }
        
        // Notify the application
        let error = pairing_failed.to_error();
        self.notify_event(SmpEvent::PairingFailed(remote_addr, error))?;
        
        Ok(())
    }
    
    /// Handle encryption information
    fn handle_encryption_information(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the encryption information
        let encryption_info = EncryptionInformation::parse(data)?;
        
        // Get the pairing process
        let mut process = {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr).ok_or(SmpError::InvalidState)?
        };
        
        // Store the LTK
        process.ltk = Some(encryption_info.ltk);
        
        // Store the updated process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        Ok(())
    }
    
    /// Handle master identification
    fn handle_master_identification(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the master identification
        let master_id = MasterIdentification::parse(data)?;
        
        // Get the pairing process
        let mut process = {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.get_mut(&remote_addr).ok_or(SmpError::InvalidState)?.clone()
        };
        
        // Check if we've received an LTK
        if let Some(ltk) = &process.ltk {
            // Generate keys for storage
            let mut keys = DeviceKeys::new();
            
            // Create LTK
            let authenticated = match process.method {
                Some(PairingMethod::JustWorks) => false,
                _ => true,
            };
            
            if process.secure_connections {
                keys.ltk = Some(LongTermKey::new_secure_connections(*ltk, authenticated));
            } else {
                keys.ltk = Some(LongTermKey::new(
                    *ltk,
                    master_id.ediv,
                    master_id.rand,
                    false,
                    authenticated
                ));
            }
            
            // Store the keys if this completes the key distribution
            self.check_key_distribution_complete(remote_addr, &mut process, keys)?;
        }
        
        Ok(())
    }
    
    /// Handle identity information
    fn handle_identity_information(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the identity information
        let identity_info = IdentityInformation::parse(data)?;
        
        // Get the pairing process
        let mut process = {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr).ok_or(SmpError::InvalidState)?
        };
        
        // Store the IRK
        process.remote_irk = Some(identity_info.irk);
        
        // Store the updated process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        // Notify the application
        self.notify_event(SmpEvent::IdentityResolvingKeyReceived(remote_addr, identity_info.irk))?;
        
        Ok(())
    }
    
    /// Handle identity address information
    fn handle_identity_address_information(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the identity address information
        let identity_addr = IdentityAddressInformation::parse(data)?;
        
        // Get the pairing process
        let mut process = {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr).ok_or(SmpError::InvalidState)?
        };
        
        // Store the identity address
        process.remote_identity = Some(IdentityAddressInfo {
            addr_type: identity_addr.addr_type,
            bd_addr: identity_addr.bd_addr,
        });
        
        // Store the updated process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        Ok(())
    }
    
    /// Handle signing information
    fn handle_signing_information(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the signing information
        let signing_info = SigningInformation::parse(data)?;
        
        // Get the pairing process
        let mut process = {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr).ok_or(SmpError::InvalidState)?
        };
        
        // Store the CSRK
        process.remote_csrk = Some(signing_info.csrk);
        
        // Store the updated process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        // Notify the application
        self.notify_event(SmpEvent::SigningKeyReceived(remote_addr, signing_info.csrk))?;
        
        Ok(())
    }
    
    /// Handle security request packet
    fn handle_security_request_packet(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the security request
        let security_req = SecurityRequest::parse(data)?;
        
        // Handle the security request
        self.handle_security_request(remote_addr, security_req.auth_req)
    }
    
    /// Handle pairing public key
    fn handle_pairing_public_key(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the public key
        let public_key = PairingPublicKey::parse(data)?;
        
        // Get the pairing process
        let mut process = {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr).ok_or(SmpError::InvalidState)?
        };
        
        // Store the remote public key
        process.remote_public_key = Some(public_key.to_bytes());
        
        // Handle based on role
        if process.role == PairingRole::Responder {
            // As responder, send our public key
            if let Some(local_public_key) = &process.local_public_key {
                let pk = PairingPublicKey::from_bytes(local_public_key);
                self.send_pairing_public_key(remote_addr, pk)?;
            } else {
                // Missing public key
                return self.send_pairing_failed(remote_addr, SMP_REASON_UNSPECIFIED_REASON);
            }
        }
        
        // Generate DHKey
        if let (Some(local_private_key), Some(remote_public_key)) = 
            (&process.local_private_key, &process.remote_public_key) {
            
            process.dhkey = Some(generate_dhkey(local_private_key, remote_public_key));
            
            // Handle Secure Connections method
            match process.method {
                Some(PairingMethod::JustWorks) => {
                    // Just Works - No user input
                    // This is a placeholder for SC Just Works handling
                },
                Some(PairingMethod::NumericComparison) => {
                    // Numeric Comparison
                    // This is a placeholder for SC Numeric Comparison handling
                },
                Some(PairingMethod::PasskeyEntry) => {
                    // Passkey Entry
                    // This is a placeholder for SC Passkey Entry handling
                },
                Some(PairingMethod::OutOfBand) => {
                    // Out of Band
                    // This is a placeholder for SC OOB handling
                },
                None => {
                    // No method selected
                    return self.send_pairing_failed(remote_addr, SMP_REASON_UNSPECIFIED_REASON);
                }
            }
            
            // Update state
            process.state = PairingState::WaitingDhKeyCheck;
        }
        
        // Store the updated process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        Ok(())
    }
    
    /// Handle pairing DHKey check
    fn handle_pairing_dhkey_check(&self, remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the DHKey check
        let dhkey_check = PairingDhKeyCheck::parse(data)?;
        
        // Get the pairing process
        let mut process = {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr).ok_or(SmpError::InvalidState)?
        };
        
        // Verify DHKey check
        // This is a placeholder for SC DHKey verification
        
        // Send our DHKey check if we're responder
        if process.role == PairingRole::Responder {
            // Generate DHKey check
            // This is a placeholder for SC DHKey check generation
            let check = [0u8; 16]; // Placeholder
            
            let dhkey_check = PairingDhKeyCheck::new(check);
            self.send_pairing_dhkey_check(remote_addr, dhkey_check)?;
        }
        
        // Complete the SC pairing
        // This is a placeholder for SC pairing completion
        
        // Complete pairing
        process.state = PairingState::Complete;
        
        // Notify the application
        self.notify_event(SmpEvent::PairingComplete(remote_addr, true))?;
        
        // Store the updated process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.insert(remote_addr, process);
        }
        
        Ok(())
    }
    
    /// Handle keypress notification
    fn handle_keypress_notification(&self, _remote_addr: BdAddr, data: &[u8]) -> SmpResult<()> {
        // Parse the keypress notification
        let _keypress = KeypressNotification::parse(data)?;
        
        // No action required for keypress notifications
        // They are informational only
        
        Ok(())
    }
    
    // Methods for sending SMP messages
    
    /// Send a pairing request
    fn send_pairing_request(&self, remote_addr: BdAddr, req: PairingRequest) -> SmpResult<()> {
        let packet = req.serialize(true);
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send a pairing response
    fn send_pairing_response(&self, remote_addr: BdAddr, rsp: PairingRequest) -> SmpResult<()> {
        let packet = rsp.serialize(false);
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send a pairing confirm
    fn send_pairing_confirm(&self, remote_addr: BdAddr, confirm: PairingConfirm) -> SmpResult<()> {
        let packet = confirm.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send a pairing random
    fn send_pairing_random(&self, remote_addr: BdAddr, random: PairingRandom) -> SmpResult<()> {
        let packet = random.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send a pairing failed
    fn send_pairing_failed(&self, remote_addr: BdAddr, reason: u8) -> SmpResult<()> {
        let failed = PairingFailed::new(reason);
        let packet = failed.serialize();
        
        // Remove the pairing process
        {
            let mut pairing_processes = self.pairing_processes.write().unwrap();
            pairing_processes.remove(&remote_addr);
        }
        
        // Notify the application
        self.notify_event(SmpEvent::PairingFailed(remote_addr, PairingFailed::new(reason).to_error()))?;
        
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send encryption information
    fn send_encryption_information(&self, remote_addr: BdAddr, ltk: [u8; 16]) -> SmpResult<()> {
        let enc_info = EncryptionInformation::new(ltk);
        let packet = enc_info.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send master identification
    fn send_master_identification(&self, remote_addr: BdAddr, ediv: u16, rand: [u8; 8]) -> SmpResult<()> {
        let master_id = MasterIdentification::new(ediv, rand);
        let packet = master_id.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send identity information
    fn send_identity_information(&self, remote_addr: BdAddr, irk: [u8; 16]) -> SmpResult<()> {
        let id_info = IdentityInformation::new(irk);
        let packet = id_info.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send identity address information
    fn send_identity_address_information(&self, remote_addr: BdAddr, addr_type: u8, bd_addr: BdAddr) -> SmpResult<()> {
        let id_addr = IdentityAddressInformation::new(addr_type, bd_addr);
        let packet = id_addr.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send signing information
    fn send_signing_information(&self, remote_addr: BdAddr, csrk: [u8; 16]) -> SmpResult<()> {
        let sign_info = SigningInformation::new(csrk);
        let packet = sign_info.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send security request
    fn send_security_request(&self, remote_addr: BdAddr, auth_req: AuthRequirements) -> SmpResult<()> {
        let sec_req = SecurityRequest::new(auth_req);
        let packet = sec_req.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send pairing public key
    fn send_pairing_public_key(&self, remote_addr: BdAddr, public_key: PairingPublicKey) -> SmpResult<()> {
        let packet = public_key.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send pairing DHKey check
    fn send_pairing_dhkey_check(&self, remote_addr: BdAddr, dhkey_check: PairingDhKeyCheck) -> SmpResult<()> {
        let packet = dhkey_check.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send keypress notification
    fn send_keypress_notification(&self, remote_addr: BdAddr, notification_type: KeypressNotificationType) -> SmpResult<()> {
        let keypress = KeypressNotification::new(notification_type);
        let packet = keypress.serialize();
        self.send_smp_packet(remote_addr, &packet)
    }
    
    /// Send an SMP packet via L2CAP
    fn send_smp_packet(&self, remote_addr: BdAddr, packet: &[u8]) -> SmpResult<()> {
        // Get the L2CAP channel ID for the device
        // In a real implementation, we would look up the L2CAP connection
        // based on the BD_ADDR, but for simplicity we'll assume it exists
        
        // Look up the HCI handle for this device
        // This would typically be stored in a map maintained by the GAP layer
        // For now, we'll use a placeholder
        let hci_handle = 0; // Placeholder
        
        // Create a map of HCI handles to L2CAP connections
        let mut handle_to_channel = HashMap::new();
        
        // Look up or create the SMP channel
        if let Ok(channel_id) = self.get_or_create_smp_channel(remote_addr, hci_handle) {
            // Send the data via L2CAP
            match self.l2cap_manager.send_data(channel_id, packet) {
                Ok(_) => Ok(()),
                Err(e) => Err(SmpError::L2capError(e.to_string())),
            }
        } else {
            Err(SmpError::ConnectionNotFound)
        }
    }
    
    /// Get or create an SMP channel for a device
    fn get_or_create_smp_channel(&self, remote_addr: BdAddr, hci_handle: u16) -> SmpResult<u16> {
        // In a real implementation, we would either look up an existing channel
        // or create a new one if it doesn't exist.
        
        // For simplicity, we'll create a new channel each time
        // In a real implementation, we would maintain a map of BD_ADDR to channel IDs
        
        // Register a PSM for SMP if not already registered
        let data_callback = Arc::new(Mutex::new(move |data: &[u8]| -> L2capResult<()> {
            // This is where we would process incoming SMP packets
            println!("Received SMP packet: {:?}", data);
            Ok(())
        }));
        
        // Create a connection policy
        let policy = crate::l2cap::ConnectionPolicy {
            min_security_level: SecurityLevel::None,
            authorization_required: false,
            auto_accept: true,
        };
        
        // Try to get the SMP fixed channel (CID = 6)
        // Normally, this would involve looking up the L2CAP connection
        // and finding the channel with the SMP CID
        
        // For simplicity, we'll just return a fixed channel ID
        Ok(SMP_CID)
    }
    
    /// Notify the application of an SMP event
    fn notify_event(&self, event: SmpEvent) -> SmpResult<()> {
        let event_callback = self.event_callback.lock().unwrap();
        if let Some(ref callback) = *event_callback {
            let mut callback = callback.lock().unwrap();
            (*callback)(event)?;
        }
        
        Ok(())
    }
    
    /// Check if key distribution is complete
    fn check_key_distribution_complete(
        &self,
        remote_addr: BdAddr,
        process: &mut PairingProcess,
        keys: DeviceKeys,
    ) -> SmpResult<()> {
        // This is a placeholder for checking if key distribution is complete
        // In a real implementation, we would track which keys have been distributed
        
        if keys.has_keys() {
            // Store the keys
            let mut key_store = self.key_store.write().unwrap();
            key_store.save_keys(&remote_addr, &keys)?;
            
            // Complete pairing
            process.state = PairingState::Complete;
            
            // Notify the application
            self.notify_event(SmpEvent::PairingComplete(remote_addr, true))?;
            self.notify_event(SmpEvent::KeysReceived(remote_addr))?;
            
            // Update security level
            let security_level = keys.security_level();
            {
                let mut security_levels = self.security_levels.write().unwrap();
                security_levels.insert(remote_addr, security_level);
            }
            
            // Notify of security level change
            self.notify_event(SmpEvent::SecurityLevelChanged(remote_addr, security_level))?;
        }
        
        Ok(())
    }
}