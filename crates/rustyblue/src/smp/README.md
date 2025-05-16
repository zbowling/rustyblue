# Security Manager Protocol (SMP) Module

The Security Manager Protocol (SMP) module implements Bluetooth security features for establishing secure connections between devices.

## Overview

SMP is responsible for:
- Pairing devices securely
- Generating and distributing encryption keys
- Authenticating devices
- Managing encryption parameters

This implementation follows the [Bluetooth Core Specification v5.2, Vol 3, Part H](https://www.bluetooth.com/specifications/specs/core-specification-5-2/).

## Components

### SmpManager

Central component that manages the overall security state:
- Initiates and responds to pairing requests
- Establishes secure connections
- Manages security keys
- Interfaces with L2CAP for transport

### Pairing Process

Implements both Legacy Pairing and LE Secure Connections pairing methods:
- Just Works (no user input)
- Passkey Entry (user enters a code)
- Numeric Comparison (user confirms matching numbers)
- Out of Band (OOB) data exchange

### Cryptographic Functions

Implements the security algorithms required for LE pairing:
- AES-CMAC
- Utility functions (c1, s1, f4, f5, f6, g2)
- Key generation and diversification

### Key Management

Manages various security keys used in LE security:
- Long Term Key (LTK) - used for link encryption
- Identity Resolving Key (IRK) - used for private address resolution
- Connection Signature Resolving Key (CSRK) - used for data signing

### Key Storage

Persists security keys to enable re-connections without re-pairing:
- In-memory storage implementation
- Extensible interface for custom storage solutions

## Security Levels

The SMP module supports four security levels:

1. **No Security (Level 0)** - No encryption, no authentication
2. **Encryption Only (Level 1)** - Encrypted but not authenticated (e.g., Just Works pairing)
3. **Encryption with Authentication (Level 2)** - Encrypted with MITM protection
4. **Secure Connections (Level 3)** - LE Secure Connections with ECDH key exchange

## Usage Examples

### Initialize SMP Manager

```rust
use rustyblue::l2cap::L2capManager;
use rustyblue::hci::HciSocket;
use rustyblue::smp::{SmpManager, MemoryKeyStore, IoCapability, AuthRequirements};
use std::sync::Arc;

// Create key store
let key_store = Box::new(MemoryKeyStore::new());

// Create SMP manager
let l2cap_manager = Arc::new(L2capManager::new(rustyblue::l2cap::ConnectionType::LE));
let hci_socket = Arc::new(HciSocket::open(0).unwrap());
let mut smp_manager = SmpManager::new(l2cap_manager, hci_socket, key_store);

// Configure pairing features
smp_manager.set_io_capability(IoCapability::DisplayYesNo);
smp_manager.set_auth_requirements(AuthRequirements::secure());
```

### Pairing Process

```rust
use rustyblue::gap::BdAddr;
use rustyblue::smp::{SmpEvent, SmpResult};

// Register event callback
smp_manager.set_event_callback(|event| -> SmpResult<()> {
    match event {
        SmpEvent::PairingRequest(addr, _) => {
            println!("Pairing request from {}", addr);
        },
        SmpEvent::DisplayPasskey(addr, passkey) => {
            println!("Please display passkey {} to {}", passkey, addr);
        },
        SmpEvent::NumericComparisonRequest(addr, value) => {
            println!("Does the value {} match on device {}?", value, addr);
            // Return true if user confirms
            // In a real app, this would prompt the user for confirmation
        },
        SmpEvent::PairingComplete(addr, success) => {
            if success {
                println!("Pairing with {} completed successfully", addr);
            } else {
                println!("Pairing with {} failed", addr);
            }
        },
        _ => { /* Handle other events */ }
    }
    Ok(())
});

// Initiate pairing
let peer_address = BdAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
smp_manager.initiate_pairing(peer_address)?;
```

### Using Encryption

```rust
// Check if device is paired
if smp_manager.is_paired(&peer_address)? {
    // Get the current security level
    let security_level = smp_manager.security_level(&peer_address)?;
    
    // Check if the security level is sufficient
    if security_level.is_authenticated() {
        println!("Connection is authenticated and encrypted");
    } else if security_level.is_encrypted() {
        println!("Connection is encrypted");
    }
}
```

## Implementation Notes

### Security Best Practices

1. **Always Use MITM Protection**: For sensitive applications, set `mitm: true` in `AuthRequirements` to ensure man-in-the-middle protection.
2. **Consider Secure Connections**: Secure Connections provides the highest level of security with ECDH key exchange.
3. **Implement Proper Key Storage**: Protect stored keys in a secure location, not in plain text.
4. **User Interaction**: Design clear UI for passkey entry and numeric comparison to prevent mistakes.

### Bluetooth Specification References

- [Bluetooth Core Specification v5.2, Vol 3, Part H](https://www.bluetooth.org/docman/handlers/downloaddoc.ashx?doc_id=478726) - Security Manager Specification
- [Bluetooth Core Specification v5.2, Vol 6, Part B, Section 5.1](https://www.bluetooth.org/docman/handlers/downloaddoc.ashx?doc_id=478726) - LE Security
- [NIST SP 800-121 Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-121r2.pdf) - Guide to Bluetooth Security

## Extensions

The SMP module can be extended with:

1. **Custom Key Storage**: Implement the `KeyStore` trait to store keys in a secure database or TPM.
2. **Customized Pairing UI**: Implement the various callback functions to integrate with your application's UI.
3. **Cross-Transport Key Generation**: Generate BR/EDR keys from LE keys for dual-mode devices.