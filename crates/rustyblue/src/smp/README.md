# Security Manager Protocol (SMP)

The Security Manager Protocol (SMP) is responsible for device pairing and key distribution in Bluetooth connections, providing the security foundation for Bluetooth communications.

## Overview

The SMP module in RustyBlue implements the Bluetooth Core Specification's Security Manager Protocol, supporting both LE and Classic Bluetooth security mechanisms. It provides:

- **Pairing**: Secure pairing between devices using various methods
- **Key generation and distribution**: Creation and exchange of encryption keys
- **Encryption**: Link encryption using derived keys
- **Authentication**: Verification of device identity
- **Authorization**: Permission management for service access

## Components

### SmpManager

The central component that manages all security operations:

```rust
// Create an SMP manager
let key_store = Box::new(MemoryKeyStore::new()) as Box<dyn KeyStore + Send + Sync>;
let smp_manager = SmpManager::new(l2cap_manager, hci_socket, key_store);

// Set callbacks for security events
smp_manager.set_event_callback(|event| {
    // Handle SMP events
    Ok(())
});

// Configure security features
smp_manager.set_io_capability(IoCapability::DisplayYesNo);
smp_manager.set_auth_requirements(AuthRequirements::secure());

// Initiate pairing
smp_manager.initiate_pairing(remote_device_address)?;
```

### Pairing Methods

SMP supports multiple pairing methods to accommodate different device capabilities:

- **Just Works**: No user interaction, lowest security
- **Passkey Entry**: One device displays a passkey, the other enters it
- **Numeric Comparison**: Both devices display a number for the user to verify
- **Out-of-Band (OOB)**: Uses an external channel for key exchange

### Security Levels

The module defines different security levels:

- **Level 0**: No security (unencrypted)
- **Level 1**: Encryption without authentication (Just Works)
- **Level 2**: Encryption with authentication (MITM protection)
- **Level 3**: Secure Connections with encryption and authentication

### Key Types

Various security keys are managed:

- **Long Term Key (LTK)**: Used for link encryption
- **Identity Resolving Key (IRK)**: Used for private address resolution
- **Connection Signature Resolving Key (CSRK)**: Used for data signing
- **Link Key**: Used for BR/EDR connections

### Key Storage

The module provides a flexible storage system for security keys:

```rust
// Create a memory-based key store
let key_store = MemoryKeyStore::new();

// Or implement your own persistent storage
struct MyKeyStore { /* ... */ }
impl KeyStore for MyKeyStore {
    // Implement the required methods
}
```

## Pairing Process

The pairing process follows these general steps:

1. **Pairing Feature Exchange**: Devices exchange their capabilities
2. **Pairing Method Selection**: An appropriate method is selected
3. **Authentication Stage 1**: TK (Temporary Key) generation
4. **Authentication Stage 2**: STK/LTK (Short/Long Term Key) generation
5. **Key Distribution**: Exchange of additional security keys
6. **Link Encryption**: Secure the connection using the derived keys

## Secure Connections

The module supports Bluetooth LE Secure Connections, which provides stronger security through:

- **ECDH Key Exchange**: Using P-256 elliptic curve
- **Stronger Encryption**: 128-bit AES-CCM encryption
- **Enhanced Authentication**: More secure pairing procedures
- **Key Derivation**: More robust key generation functions

## Usage Examples

### Initiating Pairing

```rust
// Configure security features
smp_manager.set_io_capability(IoCapability::DisplayYesNo);
smp_manager.set_auth_requirements(AuthRequirements::secure());

// Initiate pairing
smp_manager.initiate_pairing(remote_device_address)?;
```

### Responding to Pairing Requests

```rust
// Set event callback to handle incoming pairing requests
smp_manager.set_event_callback(|event| {
    match event {
        SmpEvent::PairingRequest(addr, features) => {
            // Automatically handled based on configuration
            println!("Pairing request from {}: {:?}", addr, features);
        },
        SmpEvent::PasskeyRequest(addr) => {
            // User needs to input a passkey
            notify_user_for_passkey_input(addr);
        },
        SmpEvent::NumericComparisonRequest(addr, value) => {
            // User needs to confirm value matches on both devices
            notify_user_for_comparison(addr, value);
        },
        SmpEvent::PairingComplete(addr, success) => {
            println!("Pairing with {} {}", addr, 
                     if success { "succeeded" } else { "failed" });
        },
        _ => {}
    }
    Ok(())
});
```

### Handling Passkey Entry

```rust
// Set passkey callback
smp_manager.set_passkey_callback(|addr| {
    // In a real application, this would prompt the user for input
    println!("Enter passkey for device {}", addr);
    Ok(123456) // User-entered passkey
});

// Set comparison callback
smp_manager.set_comparison_callback(|addr, value| {
    // In a real application, this would prompt the user for confirmation
    println!("Confirm value {} on device {}", value, addr);
    Ok(true) // User confirmed match
});
```

### Working with Security Keys

```rust
// Check if a device is paired
if smp_manager.is_paired(&device_addr)? {
    // Get the current security level
    let level = smp_manager.security_level(&device_addr)?;
    
    if level >= SecurityLevel::EncryptionWithAuthentication {
        // Access can be granted to sensitive services
    }
}

// List all paired devices
let paired_devices = smp_manager.paired_devices()?;
for device in paired_devices {
    println!("Paired device: {}", device);
}

// Remove pairing
smp_manager.remove_pairing(&device_addr)?;
```

## Limitations

Current limitations of the SMP implementation:

1. **Secure Connections**: Only partially implemented
2. **Cross-Transport Key Generation**: Not yet implemented
3. **Cryptographic Primitives**: Placeholder implementations need to be replaced with proper crypto library
4. **Security Database**: In-memory implementation only; needs persistent storage

## Future Work

Planned improvements:

1. Complete Secure Connections implementation
2. Add proper cryptographic implementation using a crypto library
3. Implement persistent key storage
4. Add support for cross-transport key derivation
5. Enhance security level management
6. Add more robust OOB data handling