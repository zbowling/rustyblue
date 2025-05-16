//! Standalone tests for the Security Manager Protocol module
//!
//! These tests can be run with:
//! cargo test --test smp_test

use rustyblue::gap::BdAddr;
use rustyblue::smp::constants::*;
use rustyblue::smp::crypto;
use rustyblue::smp::keys::*;
use rustyblue::smp::pairing::*;
use rustyblue::smp::types::*;

#[test]
fn test_pairing_request_serialization() {
    // Create pairing features
    let features = PairingFeatures {
        io_capability: IoCapability::DisplayYesNo,
        oob_data_present: false,
        auth_req: AuthRequirements {
            bonding: true,
            mitm: true,
            secure_connections: true,
            keypress_notifications: false,
            ct2: false,
        },
        max_key_size: 16,
        initiator_key_dist: KeyDistribution::all(),
        responder_key_dist: KeyDistribution::all(),
    };

    // Create pairing request
    let req = PairingRequest::from_features(&features);

    // Serialize
    let data = req.serialize(true);

    // Verify format
    assert_eq!(data.len(), 7);
    assert_eq!(data[0], SMP_PAIRING_REQUEST);
    assert_eq!(data[1], IoCapability::DisplayYesNo.to_u8());
    assert_eq!(data[2], 0); // OOB data not present
    assert_eq!(
        data[3],
        SMP_AUTH_REQ_BONDING | SMP_AUTH_REQ_MITM | SMP_AUTH_REQ_SC
    );
    assert_eq!(data[4], 16); // Key size
    assert_eq!(data[5], 7); // Initiator keys
    assert_eq!(data[6], 7); // Responder keys

    // Parse back
    let parsed_req = PairingRequest::parse(&data).unwrap();
    let parsed_features = parsed_req.to_features();

    // Verify features match
    assert_eq!(parsed_features.io_capability, features.io_capability);
    assert_eq!(parsed_features.oob_data_present, features.oob_data_present);
    assert_eq!(parsed_features.auth_req.bonding, features.auth_req.bonding);
    assert_eq!(parsed_features.auth_req.mitm, features.auth_req.mitm);
    assert_eq!(
        parsed_features.auth_req.secure_connections,
        features.auth_req.secure_connections
    );
    assert_eq!(parsed_features.max_key_size, features.max_key_size);
}

#[test]
fn test_pairing_confirm() {
    // Create confirm value
    let confirm_value = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];

    // Create pairing confirm
    let confirm = PairingConfirm::new(confirm_value);

    // Serialize
    let data = confirm.serialize();

    // Verify format
    assert_eq!(data.len(), 17);
    assert_eq!(data[0], SMP_PAIRING_CONFIRM);
    assert_eq!(&data[1..17], &confirm_value);

    // Parse back
    let parsed_confirm = PairingConfirm::parse(&data).unwrap();

    // Verify confirm value matches
    assert_eq!(parsed_confirm.confirm_value, confirm_value);
}

#[test]
fn test_random_generation() {
    // Generate random values
    let rand1 = crypto::generate_random_128();
    let rand2 = crypto::generate_random_128();

    // Verify they're different (extremely unlikely they'd be the same)
    assert_ne!(rand1, rand2);

    // Verify correct size
    assert_eq!(rand1.len(), 16);
    assert_eq!(rand2.len(), 16);
}

#[test]
fn test_auth_requirements() {
    // Create auth requirements
    let auth_req = AuthRequirements {
        bonding: true,
        mitm: true,
        secure_connections: true,
        keypress_notifications: false,
        ct2: false,
    };

    // Convert to u8
    let auth_byte = auth_req.to_u8();

    // Verify flags
    assert_eq!(auth_byte & SMP_AUTH_REQ_BONDING, SMP_AUTH_REQ_BONDING);
    assert_eq!(auth_byte & SMP_AUTH_REQ_MITM, SMP_AUTH_REQ_MITM);
    assert_eq!(auth_byte & SMP_AUTH_REQ_SC, SMP_AUTH_REQ_SC);
    assert_eq!(auth_byte & SMP_AUTH_REQ_KEYPRESS, 0);
    assert_eq!(auth_byte & SMP_AUTH_REQ_CT2, 0);

    // Convert back
    let parsed_auth = AuthRequirements::from_u8(auth_byte);

    // Verify fields match
    assert_eq!(parsed_auth.bonding, auth_req.bonding);
    assert_eq!(parsed_auth.mitm, auth_req.mitm);
    assert_eq!(parsed_auth.secure_connections, auth_req.secure_connections);
    assert_eq!(
        parsed_auth.keypress_notifications,
        auth_req.keypress_notifications
    );
    assert_eq!(parsed_auth.ct2, auth_req.ct2);
}

#[test]
fn test_key_distribution() {
    // Create key distribution preferences
    let key_dist = KeyDistribution::all();

    // Convert to u8
    let key_byte = key_dist.to_u8();

    // Verify flags
    assert_eq!(key_byte & SMP_KEY_DIST_ENC_KEY, SMP_KEY_DIST_ENC_KEY);
    assert_eq!(key_byte & SMP_KEY_DIST_ID_KEY, SMP_KEY_DIST_ID_KEY);
    assert_eq!(key_byte & SMP_KEY_DIST_SIGN_KEY, SMP_KEY_DIST_SIGN_KEY);
    assert_eq!(key_byte & SMP_KEY_DIST_LINK_KEY, 0); // Default is false

    // Convert back
    let parsed_key_dist = KeyDistribution::from_u8(key_byte);

    // Verify fields match
    assert_eq!(parsed_key_dist.encryption_key, key_dist.encryption_key);
    assert_eq!(parsed_key_dist.identity_key, key_dist.identity_key);
    assert_eq!(parsed_key_dist.signing_key, key_dist.signing_key);
    assert_eq!(parsed_key_dist.link_key, key_dist.link_key);
}

#[test]
fn test_security_level_conversion() {
    // Test SMP to L2CAP conversion
    let smp_none = SecurityLevel::None;
    let smp_enc = SecurityLevel::EncryptionOnly;
    let smp_auth = SecurityLevel::EncryptionWithAuthentication;
    let smp_sc = SecurityLevel::SecureConnections;

    let l2cap_none: rustyblue::l2cap::types::SecurityLevel = smp_none.into();
    let l2cap_enc: rustyblue::l2cap::types::SecurityLevel = smp_enc.into();
    let l2cap_auth: rustyblue::l2cap::types::SecurityLevel = smp_auth.into();
    let l2cap_sc: rustyblue::l2cap::types::SecurityLevel = smp_sc.into();

    assert_eq!(l2cap_none, rustyblue::l2cap::types::SecurityLevel::None);
    assert_eq!(
        l2cap_enc,
        rustyblue::l2cap::types::SecurityLevel::Authentication
    );
    assert_eq!(
        l2cap_auth,
        rustyblue::l2cap::types::SecurityLevel::AuthenticationAndEncryption
    );
    assert_eq!(
        l2cap_sc,
        rustyblue::l2cap::types::SecurityLevel::SecureConnectionsWithEncryption
    );

    // Test L2CAP to SMP conversion
    let l2cap_none = rustyblue::l2cap::types::SecurityLevel::None;
    let l2cap_auth = rustyblue::l2cap::types::SecurityLevel::Authentication;
    let l2cap_auth_enc = rustyblue::l2cap::types::SecurityLevel::AuthenticationAndEncryption;
    let l2cap_sc = rustyblue::l2cap::types::SecurityLevel::SecureConnectionsWithEncryption;

    let smp_none2: SecurityLevel = l2cap_none.into();
    let smp_auth2: SecurityLevel = l2cap_auth.into();
    let smp_auth_enc2: SecurityLevel = l2cap_auth_enc.into();
    let smp_sc2: SecurityLevel = l2cap_sc.into();

    assert_eq!(smp_none2, SecurityLevel::None);
    assert_eq!(smp_auth2, SecurityLevel::EncryptionWithAuthentication);
    assert_eq!(smp_auth_enc2, SecurityLevel::EncryptionWithAuthentication);
    assert_eq!(smp_sc2, SecurityLevel::SecureConnections);
}

#[test]
fn test_memory_key_store() {
    // Create key store
    let mut key_store = MemoryKeyStore::new();

    // Create device address
    let addr = BdAddr::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

    // Create some keys
    let mut keys = DeviceKeys::new();
    let ltk = LongTermKey::new_secure_connections([0x01; 16], true);
    keys.ltk = Some(ltk);

    // Save keys
    key_store.save_keys(&addr, &keys).unwrap();

    // Load keys
    let loaded_keys = key_store.load_keys(&addr).unwrap().unwrap();

    // Verify LTK
    assert!(loaded_keys.ltk.is_some());
    let loaded_ltk = loaded_keys.ltk.unwrap();
    assert_eq!(loaded_ltk.key, [0x01; 16]);
    assert_eq!(loaded_ltk.secure_connections, true);
    assert_eq!(loaded_ltk.authenticated, true);

    // Get all paired devices
    let paired_devices = key_store.get_paired_devices().unwrap();
    assert_eq!(paired_devices.len(), 1);
    assert_eq!(paired_devices[0], addr);

    // Delete keys
    key_store.delete_keys(&addr).unwrap();

    // Verify keys are gone
    let loaded_keys = key_store.load_keys(&addr).unwrap();
    assert!(loaded_keys.is_none());
}
