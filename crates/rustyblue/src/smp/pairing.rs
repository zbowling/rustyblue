//! Pairing implementation for the Security Manager Protocol
//!
//! This module handles the pairing process, including the state machine
//! for both legacy pairing and LE Secure Connections.

use super::constants::*;
use super::crypto::*;
use super::keys::*;
use super::types::*;
use crate::gap::BdAddr;
use crate::l2cap::*;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{Cursor, Read, Write};
use std::time::{Duration, Instant};

/// Pairing request/response packet
#[derive(Debug, Clone)]
pub struct PairingRequest {
    /// IO capability
    pub io_capability: u8,
    /// OOB data flag
    pub oob_data_present: u8,
    /// Authentication requirements
    pub auth_req: u8,
    /// Maximum encryption key size
    pub max_key_size: u8,
    /// Initiator key distribution
    pub initiator_key_dist: u8,
    /// Responder key distribution
    pub responder_key_dist: u8,
}

impl PairingRequest {
    /// Create new pairing request
    pub fn new(
        io_capability: IoCapability,
        oob_data_present: bool,
        auth_req: AuthRequirements,
        max_key_size: u8,
        initiator_key_dist: KeyDistribution,
        responder_key_dist: KeyDistribution,
    ) -> Self {
        Self {
            io_capability: io_capability.to_u8(),
            oob_data_present: if oob_data_present { 1 } else { 0 },
            auth_req: auth_req.to_u8(),
            max_key_size,
            initiator_key_dist: initiator_key_dist.to_u8(),
            responder_key_dist: responder_key_dist.to_u8(),
        }
    }

    /// Create from PairingFeatures
    pub fn from_features(features: &PairingFeatures) -> Self {
        Self {
            io_capability: features.io_capability.to_u8(),
            oob_data_present: if features.oob_data_present { 1 } else { 0 },
            auth_req: features.auth_req.to_u8(),
            max_key_size: features.max_key_size,
            initiator_key_dist: features.initiator_key_dist.to_u8(),
            responder_key_dist: features.responder_key_dist.to_u8(),
        }
    }

    /// Convert to PairingFeatures
    pub fn to_features(&self) -> PairingFeatures {
        PairingFeatures {
            io_capability: IoCapability::from_u8(self.io_capability)
                .unwrap_or(IoCapability::NoInputNoOutput),
            oob_data_present: self.oob_data_present != 0,
            auth_req: AuthRequirements::from_u8(self.auth_req),
            max_key_size: self.max_key_size,
            initiator_key_dist: KeyDistribution::from_u8(self.initiator_key_dist),
            responder_key_dist: KeyDistribution::from_u8(self.responder_key_dist),
        }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 7 {
            return Err(SmpError::InvalidParameter(
                "Pairing request too short".into(),
            ));
        }

        Ok(Self {
            io_capability: data[1],
            oob_data_present: data[2],
            auth_req: data[3],
            max_key_size: data[4],
            initiator_key_dist: data[5],
            responder_key_dist: data[6],
        })
    }

    /// Serialize to raw packet
    pub fn serialize(&self, is_request: bool) -> Vec<u8> {
        let mut packet = Vec::with_capacity(7);

        packet.push(if is_request {
            SMP_PAIRING_REQUEST
        } else {
            SMP_PAIRING_RESPONSE
        });
        packet.push(self.io_capability);
        packet.push(self.oob_data_present);
        packet.push(self.auth_req);
        packet.push(self.max_key_size);
        packet.push(self.initiator_key_dist);
        packet.push(self.responder_key_dist);

        packet
    }
}

/// Pairing confirm packet
#[derive(Debug, Clone)]
pub struct PairingConfirm {
    /// Confirm value
    pub confirm_value: [u8; 16],
}

impl PairingConfirm {
    /// Create new pairing confirm
    pub fn new(confirm_value: [u8; 16]) -> Self {
        Self { confirm_value }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 17 {
            return Err(SmpError::InvalidParameter(
                "Pairing confirm too short".into(),
            ));
        }

        let mut confirm_value = [0u8; 16];
        confirm_value.copy_from_slice(&data[1..17]);

        Ok(Self { confirm_value })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(17);

        packet.push(SMP_PAIRING_CONFIRM);
        packet.extend_from_slice(&self.confirm_value);

        packet
    }
}

/// Pairing random packet
#[derive(Debug, Clone)]
pub struct PairingRandom {
    /// Random value
    pub random_value: [u8; 16],
}

impl PairingRandom {
    /// Create new pairing random
    pub fn new(random_value: [u8; 16]) -> Self {
        Self { random_value }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 17 {
            return Err(SmpError::InvalidParameter(
                "Pairing random too short".into(),
            ));
        }

        let mut random_value = [0u8; 16];
        random_value.copy_from_slice(&data[1..17]);

        Ok(Self { random_value })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(17);

        packet.push(SMP_PAIRING_RANDOM);
        packet.extend_from_slice(&self.random_value);

        packet
    }
}

/// Pairing failed packet
#[derive(Debug, Clone)]
pub struct PairingFailed {
    /// Reason code
    pub reason: u8,
}

impl PairingFailed {
    /// Create new pairing failed
    pub fn new(reason: u8) -> Self {
        Self { reason }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 2 {
            return Err(SmpError::InvalidParameter(
                "Pairing failed too short".into(),
            ));
        }

        Ok(Self { reason: data[1] })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(2);

        packet.push(SMP_PAIRING_FAILED);
        packet.push(self.reason);

        packet
    }

    /// Convert reason code to SmpError
    pub fn to_error(&self) -> SmpError {
        match self.reason {
            SMP_REASON_PASSKEY_ENTRY_FAILED => SmpError::PasskeyEntryFailed,
            SMP_REASON_OOB_NOT_AVAILABLE => SmpError::OobNotAvailable,
            SMP_REASON_AUTHENTICATION_REQUIREMENTS => SmpError::AuthenticationRequirements,
            SMP_REASON_CONFIRM_VALUE_FAILED => SmpError::ConfirmValueFailed,
            SMP_REASON_PAIRING_NOT_SUPPORTED => SmpError::PairingNotSupported,
            SMP_REASON_ENCRYPTION_KEY_SIZE => SmpError::EncryptionKeySize,
            SMP_REASON_COMMAND_NOT_SUPPORTED => SmpError::CommandNotSupported,
            SMP_REASON_UNSPECIFIED_REASON => SmpError::UnspecifiedReason,
            SMP_REASON_REPEATED_ATTEMPTS => SmpError::RepeatedAttempts,
            SMP_REASON_INVALID_PARAMETERS => SmpError::InvalidParameters,
            SMP_REASON_DHKEY_CHECK_FAILED => SmpError::DhKeyCheckFailed,
            SMP_REASON_NUMERIC_COMPARISON_FAILED => SmpError::NumericComparisonFailed,
            SMP_REASON_BR_EDR_PAIRING_IN_PROGRESS => SmpError::BrEdrPairingInProgress,
            SMP_REASON_CROSS_TRANSPORT_KEY_NOT_ALLOWED => SmpError::CrossTransportKeyNotAllowed,
            _ => SmpError::UnspecifiedReason,
        }
    }
}

/// Encryption information packet
#[derive(Debug, Clone)]
pub struct EncryptionInformation {
    /// Long Term Key
    pub ltk: [u8; 16],
}

impl EncryptionInformation {
    /// Create new encryption information
    pub fn new(ltk: [u8; 16]) -> Self {
        Self { ltk }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 17 {
            return Err(SmpError::InvalidParameter(
                "Encryption information too short".into(),
            ));
        }

        let mut ltk = [0u8; 16];
        ltk.copy_from_slice(&data[1..17]);

        Ok(Self { ltk })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(17);

        packet.push(SMP_ENCRYPTION_INFORMATION);
        packet.extend_from_slice(&self.ltk);

        packet
    }
}

/// Master identification packet
#[derive(Debug, Clone)]
pub struct MasterIdentification {
    /// EDIV (Encrypted Diversifier)
    pub ediv: u16,
    /// RAND (Random number)
    pub rand: [u8; 8],
}

impl MasterIdentification {
    /// Create new master identification
    pub fn new(ediv: u16, rand: [u8; 8]) -> Self {
        Self { ediv, rand }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 11 {
            return Err(SmpError::InvalidParameter(
                "Master identification too short".into(),
            ));
        }

        let mut cursor = Cursor::new(&data[1..]);
        let ediv = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| SmpError::InvalidParameter("Failed to read EDIV".into()))?;

        let mut rand = [0u8; 8];
        cursor
            .read_exact(&mut rand)
            .map_err(|_| SmpError::InvalidParameter("Failed to read RAND".into()))?;

        Ok(Self { ediv, rand })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(11);

        packet.push(SMP_MASTER_IDENTIFICATION);
        packet.extend_from_slice(&self.ediv.to_le_bytes());
        packet.extend_from_slice(&self.rand);

        packet
    }
}

/// Identity information packet
#[derive(Debug, Clone)]
pub struct IdentityInformation {
    /// Identity Resolving Key
    pub irk: [u8; 16],
}

impl IdentityInformation {
    /// Create new identity information
    pub fn new(irk: [u8; 16]) -> Self {
        Self { irk }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 17 {
            return Err(SmpError::InvalidParameter(
                "Identity information too short".into(),
            ));
        }

        let mut irk = [0u8; 16];
        irk.copy_from_slice(&data[1..17]);

        Ok(Self { irk })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(17);

        packet.push(SMP_IDENTITY_INFORMATION);
        packet.extend_from_slice(&self.irk);

        packet
    }
}

/// Identity address information packet
#[derive(Debug, Clone)]
pub struct IdentityAddressInformation {
    /// Address type
    pub addr_type: u8,
    /// Bluetooth device address
    pub bd_addr: BdAddr,
}

impl IdentityAddressInformation {
    /// Create new identity address information
    pub fn new(addr_type: u8, bd_addr: BdAddr) -> Self {
        Self { addr_type, bd_addr }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 8 {
            return Err(SmpError::InvalidParameter(
                "Identity address information too short".into(),
            ));
        }

        let addr_type = data[1];

        let mut bd_addr_bytes = [0u8; 6];
        bd_addr_bytes.copy_from_slice(&data[2..8]);
        bd_addr_bytes.reverse(); // HCI addresses are little-endian
        let bd_addr = BdAddr::new(bd_addr_bytes);

        Ok(Self { addr_type, bd_addr })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(8);

        packet.push(SMP_IDENTITY_ADDRESS_INFORMATION);
        packet.push(self.addr_type);
        packet.extend_from_slice(&self.bd_addr.bytes);

        packet
    }
}

/// Signing information packet
#[derive(Debug, Clone)]
pub struct SigningInformation {
    /// Connection Signature Resolving Key
    pub csrk: [u8; 16],
}

impl SigningInformation {
    /// Create new signing information
    pub fn new(csrk: [u8; 16]) -> Self {
        Self { csrk }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 17 {
            return Err(SmpError::InvalidParameter(
                "Signing information too short".into(),
            ));
        }

        let mut csrk = [0u8; 16];
        csrk.copy_from_slice(&data[1..17]);

        Ok(Self { csrk })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(17);

        packet.push(SMP_SIGNING_INFORMATION);
        packet.extend_from_slice(&self.csrk);

        packet
    }
}

/// Security request packet
#[derive(Debug, Clone)]
pub struct SecurityRequest {
    /// Authentication requirements
    pub auth_req: u8,
}

impl SecurityRequest {
    /// Create new security request
    pub fn new(auth_req: AuthRequirements) -> Self {
        Self {
            auth_req: auth_req.to_u8(),
        }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 2 {
            return Err(SmpError::InvalidParameter(
                "Security request too short".into(),
            ));
        }

        Ok(Self { auth_req: data[1] })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(2);

        packet.push(SMP_SECURITY_REQUEST);
        packet.push(self.auth_req);

        packet
    }

    /// Convert to AuthRequirements
    pub fn to_auth_requirements(&self) -> AuthRequirements {
        AuthRequirements::from_u8(self.auth_req)
    }
}

/// Pairing public key packet
#[derive(Debug, Clone)]
pub struct PairingPublicKey {
    /// Public key X coordinate
    pub x: [u8; 32],
    /// Public key Y coordinate
    pub y: [u8; 32],
}

impl PairingPublicKey {
    /// Create new pairing public key
    pub fn new(x: [u8; 32], y: [u8; 32]) -> Self {
        Self { x, y }
    }

    /// Create from 64-byte key
    pub fn from_bytes(key: &[u8; 64]) -> Self {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];

        x.copy_from_slice(&key[0..32]);
        y.copy_from_slice(&key[32..64]);

        Self { x, y }
    }

    /// Convert to 64-byte key
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut key = [0u8; 64];

        key[0..32].copy_from_slice(&self.x);
        key[32..64].copy_from_slice(&self.y);

        key
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 65 {
            return Err(SmpError::InvalidParameter(
                "Pairing public key too short".into(),
            ));
        }

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];

        x.copy_from_slice(&data[1..33]);
        y.copy_from_slice(&data[33..65]);

        Ok(Self { x, y })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(65);

        packet.push(SMP_PAIRING_PUBLIC_KEY);
        packet.extend_from_slice(&self.x);
        packet.extend_from_slice(&self.y);

        packet
    }
}

/// Pairing DHKey check packet
#[derive(Debug, Clone)]
pub struct PairingDhKeyCheck {
    /// DHKey check value
    pub check: [u8; 16],
}

impl PairingDhKeyCheck {
    /// Create new pairing DHKey check
    pub fn new(check: [u8; 16]) -> Self {
        Self { check }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 17 {
            return Err(SmpError::InvalidParameter(
                "Pairing DHKey check too short".into(),
            ));
        }

        let mut check = [0u8; 16];
        check.copy_from_slice(&data[1..17]);

        Ok(Self { check })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(17);

        packet.push(SMP_PAIRING_DHK_CHECK);
        packet.extend_from_slice(&self.check);

        packet
    }
}

/// Keypress notification packet
#[derive(Debug, Clone)]
pub struct KeypressNotification {
    /// Notification type
    pub notification_type: u8,
}

impl KeypressNotification {
    /// Create new keypress notification
    pub fn new(notification_type: KeypressNotificationType) -> Self {
        Self {
            notification_type: notification_type.to_u8(),
        }
    }

    /// Parse from raw packet
    pub fn parse(data: &[u8]) -> SmpResult<Self> {
        if data.len() < 2 {
            return Err(SmpError::InvalidParameter(
                "Keypress notification too short".into(),
            ));
        }

        Ok(Self {
            notification_type: data[1],
        })
    }

    /// Serialize to raw packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(2);

        packet.push(SMP_PAIRING_KEYPRESS_NOTIFICATION);
        packet.push(self.notification_type);

        packet
    }

    /// Convert to KeypressNotificationType
    pub fn to_notification_type(&self) -> Option<KeypressNotificationType> {
        KeypressNotificationType::from_u8(self.notification_type)
    }
}

/// Pairing state machine state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    /// Idle state
    Idle,
    /// Waiting for pairing response
    WaitingPairingResponse,
    /// Waiting for pairing confirm
    WaitingPairingConfirm,
    /// Waiting for pairing random
    WaitingPairingRandom,
    /// Waiting for public key
    WaitingPublicKey,
    /// Waiting for DHKey check
    WaitingDhKeyCheck,
    /// Waiting for key distribution
    WaitingKeyDistribution,
    /// Pairing complete
    Complete,
    /// Pairing failed
    Failed,
}

/// Pairing process
pub struct PairingProcess {
    /// Remote device address
    pub remote_addr: BdAddr,
    /// Local pairing features
    pub local_features: PairingFeatures,
    /// Remote pairing features
    pub remote_features: Option<PairingFeatures>,
    /// Pairing role (initiator or responder)
    pub role: PairingRole,
    /// Whether secure connections is being used
    pub secure_connections: bool,
    /// Pairing method
    pub method: Option<PairingMethod>,
    /// Current state of the pairing process
    pub state: PairingState,
    /// Local random value
    pub local_random: Option<[u8; 16]>,
    /// Local confirm value
    pub local_confirm: Option<[u8; 16]>,
    /// Remote random value
    pub remote_random: Option<[u8; 16]>,
    /// Remote confirm value
    pub remote_confirm: Option<[u8; 16]>,
    /// Temporary key for LE legacy pairing
    pub tk: Option<[u8; 16]>,
    /// Passkey for entry/comparison
    pub passkey: Option<u32>,
    /// Passkey bits used (for secure connections)
    pub passkey_bits_used: u8,
    /// Local ECDH private key
    pub local_private_key: Option<[u8; 32]>,
    /// Local ECDH public key
    pub local_public_key: Option<[u8; 64]>,
    /// Remote ECDH public key
    pub remote_public_key: Option<[u8; 64]>,
    /// DHKey
    pub dhkey: Option<[u8; 32]>,
    /// MacKey (for secure connections)
    pub mackey: Option<[u8; 16]>,
    /// Long Term Key
    pub ltk: Option<[u8; 16]>,
    /// Identity Resolving Key received
    pub remote_irk: Option<[u8; 16]>,
    /// Signature Resolving Key received
    pub remote_csrk: Option<[u8; 16]>,
    /// Identity address received
    pub remote_identity: Option<IdentityAddressInfo>,
    /// Timestamp for timeout
    pub timestamp: Instant,
}

impl PairingProcess {
    /// Create a new pairing process as initiator
    pub fn new_initiator(remote_addr: BdAddr, features: PairingFeatures) -> Self {
        let secure_connections = features.auth_req.secure_connections;
        Self {
            remote_addr,
            local_features: features,
            remote_features: None,
            role: PairingRole::Initiator,
            secure_connections,
            method: None,
            state: PairingState::Idle,
            local_random: None,
            local_confirm: None,
            remote_random: None,
            remote_confirm: None,
            tk: None,
            passkey: None,
            passkey_bits_used: 0,
            local_private_key: None,
            local_public_key: None,
            remote_public_key: None,
            dhkey: None,
            mackey: None,
            ltk: None,
            remote_irk: None,
            remote_csrk: None,
            remote_identity: None,
            timestamp: Instant::now(),
        }
    }

    /// Create a new pairing process as responder
    pub fn new_responder(remote_addr: BdAddr, features: PairingFeatures) -> Self {
        let secure_connections = features.auth_req.secure_connections;
        Self {
            remote_addr,
            local_features: features,
            remote_features: None,
            role: PairingRole::Responder,
            secure_connections,
            method: None,
            state: PairingState::Idle,
            local_random: None,
            local_confirm: None,
            remote_random: None,
            remote_confirm: None,
            tk: None,
            passkey: None,
            passkey_bits_used: 0,
            local_private_key: None,
            local_public_key: None,
            remote_public_key: None,
            dhkey: None,
            mackey: None,
            ltk: None,
            remote_irk: None,
            remote_csrk: None,
            remote_identity: None,
            timestamp: Instant::now(),
        }
    }

    /// Get the combined key distribution
    pub fn key_distribution(&self) -> Option<(KeyDistribution, KeyDistribution)> {
        if let Some(remote_features) = &self.remote_features {
            // Combine local and remote preferences
            let initiator_key_dist = if self.role == PairingRole::Initiator {
                KeyDistribution {
                    encryption_key: self.local_features.initiator_key_dist.encryption_key
                        && remote_features.initiator_key_dist.encryption_key,
                    identity_key: self.local_features.initiator_key_dist.identity_key
                        && remote_features.initiator_key_dist.identity_key,
                    signing_key: self.local_features.initiator_key_dist.signing_key
                        && remote_features.initiator_key_dist.signing_key,
                    link_key: self.local_features.initiator_key_dist.link_key
                        && remote_features.initiator_key_dist.link_key,
                }
            } else {
                KeyDistribution {
                    encryption_key: self.local_features.responder_key_dist.encryption_key
                        && remote_features.responder_key_dist.encryption_key,
                    identity_key: self.local_features.responder_key_dist.identity_key
                        && remote_features.responder_key_dist.identity_key,
                    signing_key: self.local_features.responder_key_dist.signing_key
                        && remote_features.responder_key_dist.signing_key,
                    link_key: self.local_features.responder_key_dist.link_key
                        && remote_features.responder_key_dist.link_key,
                }
            };

            let responder_key_dist = if self.role == PairingRole::Initiator {
                KeyDistribution {
                    encryption_key: self.local_features.responder_key_dist.encryption_key
                        && remote_features.responder_key_dist.encryption_key,
                    identity_key: self.local_features.responder_key_dist.identity_key
                        && remote_features.responder_key_dist.identity_key,
                    signing_key: self.local_features.responder_key_dist.signing_key
                        && remote_features.responder_key_dist.signing_key,
                    link_key: self.local_features.responder_key_dist.link_key
                        && remote_features.responder_key_dist.link_key,
                }
            } else {
                KeyDistribution {
                    encryption_key: self.local_features.initiator_key_dist.encryption_key
                        && remote_features.initiator_key_dist.encryption_key,
                    identity_key: self.local_features.initiator_key_dist.identity_key
                        && remote_features.initiator_key_dist.identity_key,
                    signing_key: self.local_features.initiator_key_dist.signing_key
                        && remote_features.initiator_key_dist.signing_key,
                    link_key: self.local_features.initiator_key_dist.link_key
                        && remote_features.initiator_key_dist.link_key,
                }
            };

            Some((initiator_key_dist, responder_key_dist))
        } else {
            None
        }
    }

    /// Determine the pairing method
    pub fn determine_pairing_method(&mut self) -> SmpResult<PairingMethod> {
        if let Some(remote_features) = &self.remote_features {
            let local_io = self.local_features.io_capability;
            let remote_io = remote_features.io_capability;
            let local_oob = self.local_features.oob_data_present;
            let remote_oob = remote_features.oob_data_present;
            let local_mitm = self.local_features.auth_req.mitm;
            let remote_mitm = remote_features.auth_req.mitm;

            // Check for OOB
            if local_oob && remote_oob {
                return Ok(PairingMethod::OutOfBand);
            }

            // Check for Numeric Comparison (SC only)
            if self.secure_connections
                && local_io == IoCapability::DisplayYesNo
                && remote_io == IoCapability::DisplayYesNo
            {
                return Ok(PairingMethod::NumericComparison);
            }

            // Check for Passkey Entry
            if (local_io == IoCapability::KeyboardOnly && remote_io == IoCapability::DisplayOnly)
                || (local_io == IoCapability::KeyboardOnly
                    && remote_io == IoCapability::DisplayYesNo)
            {
                return Ok(PairingMethod::PasskeyEntry);
            }

            if (local_io == IoCapability::DisplayOnly && remote_io == IoCapability::KeyboardOnly)
                || (local_io == IoCapability::DisplayYesNo
                    && remote_io == IoCapability::KeyboardOnly)
            {
                return Ok(PairingMethod::PasskeyEntry);
            }

            // Fall back to Just Works
            Ok(PairingMethod::JustWorks)
        } else {
            Err(SmpError::InvalidState)
        }
    }

    /// Check if pairing is complete
    pub fn is_complete(&self) -> bool {
        self.state == PairingState::Complete
    }

    /// Check if pairing has failed
    pub fn has_failed(&self) -> bool {
        self.state == PairingState::Failed
    }

    /// Check if pairing has timed out
    pub fn has_timed_out(&self, timeout: Duration) -> bool {
        self.timestamp.elapsed() > timeout
    }

    /// Update timestamp to prevent timeout
    pub fn update_timestamp(&mut self) {
        self.timestamp = Instant::now();
    }

    /// Generate keys for this device
    pub fn generate_keys(&mut self) -> SmpResult<DeviceKeys> {
        let mut keys = DeviceKeys::new();

        // Generate LTK
        if let Some(ltk) = &self.ltk {
            let authenticated = match self.method {
                Some(PairingMethod::JustWorks) => false,
                _ => true,
            };

            if self.secure_connections {
                keys.ltk = Some(LongTermKey::new_secure_connections(*ltk, authenticated));
            } else if let Some(remote_random) = &self.remote_random {
                // In legacy pairing, we need EDIV and RAND
                let ediv = ((remote_random[0] as u16) << 8) | (remote_random[1] as u16);
                let mut rand = [0u8; 8];
                rand.copy_from_slice(&remote_random[8..16]);

                keys.ltk = Some(LongTermKey::new(*ltk, ediv, rand, false, authenticated));
            }
        }

        // Include IRK if received
        if let Some(irk) = &self.remote_irk {
            if let Some(identity) = &self.remote_identity {
                keys.irk = Some(IdentityResolvingKey::new(
                    *irk,
                    identity.addr_type,
                    identity.bd_addr,
                ));
            }
        }

        // Include CSRK if received
        if let Some(csrk) = &self.remote_csrk {
            let authenticated = match self.method {
                Some(PairingMethod::JustWorks) => false,
                _ => true,
            };

            keys.remote_csrk = Some(ConnectionSignatureResolvingKey::new(*csrk, authenticated));
        }

        Ok(keys)
    }
}
