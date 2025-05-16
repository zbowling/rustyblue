# L2CAP Module

The Logical Link Control and Adaptation Protocol (L2CAP) is a core protocol in the Bluetooth stack that provides:

- Multiplexing between different higher layer protocols
- Segmentation and reassembly of packets
- Quality of Service (QoS) capabilities
- Channel management and flow control

## Architecture

This implementation follows the Bluetooth Core Specification v5.2, Volume 3, Part A.

### Key Components

#### L2CAP Manager (`core.rs`)

The central component that manages channels and handles all protocol operations:
- Channel creation and management
- Packet routing and signaling
- Flow control and credits management (for LE)
- Connection establishment and disconnection

#### Channels (`channel.rs`)

Represents a logical L2CAP connection:
- Channel state management
- Segmentation and reassembly
- Flow control and retransmission (if enabled)
- Credit-based flow control for LE

#### Packet Handling (`packet.rs`)

Defines the structure of L2CAP packets and provides parsing/serialization:
- Basic L2CAP headers (length, CID)
- Extended headers for retransmission modes
- Segmentation support

#### Protocol/Service Multiplexers (`psm.rs`)

Identifies higher layer protocols and services:
- Standard PSM values defined by Bluetooth SIG
- Dynamic PSM allocation for LE

#### Signaling Commands (`signaling.rs`)

Implementation of the L2CAP signaling commands:
- Connection requests/responses
- Configuration requests/responses
- Disconnection requests/responses
- Credit-based flow control
- Information requests/responses

### Channel Types

1. **Fixed Channels** (CIDs 1-6)
   - L2CAP Signaling (CID 1)
   - Connectionless Reception (CID 2)
   - ATT Protocol (CID 4)
   - LE L2CAP Signaling (CID 5)
   - Security Manager Protocol (CID 6)

2. **Connection-Oriented Channels** (CIDs 0x40-0xFFFF)
   - Dynamic allocation
   - Configuration negotiation
   - Multiple operating modes
   
3. **LE Credit-Based Channels** (LE only)
   - Credit-based flow control
   - Simplified configuration

### Modes of Operation

1. **Basic Mode**
   - No retransmission or flow control
   - Best-effort delivery

2. **Enhanced Retransmission Mode**
   - Reliable delivery
   - Flow control
   - Segmentation and reassembly
   - Error recovery

3. **Streaming Mode**
   - Unreliable but sequenced delivery
   - No flow control
   - Suitable for audio/video

4. **LE Credit-Based Flow Control Mode**
   - Simplified approach for LE devices
   - Credit-based flow control
   - Reduced signaling overhead

## Usage

### Basic Connection Example

```rust
use rustyblue::l2cap::{L2capManager, PSM, ConnectionType, SecurityLevel};
use std::sync::Arc;

// Create L2CAP manager
let l2cap_manager = Arc::new(L2capManager::new(ConnectionType::LE));

// Connect to a remote device on a specific PSM
let hci_handle = 0x0042; // This would be obtained from HCI layer
let cid = l2cap_manager.connect(PSM::from_value(0x0001).unwrap(), hci_handle)?;

// Send data on the channel
l2cap_manager.send_data(cid, b"Hello, Bluetooth!")?;

// Register to receive data
l2cap_manager.register_psm(
    PSM::from_value(0x0001).unwrap(),
    Some(Arc::new(Mutex::new(|data| {
        println!("Received: {:?}", data);
        Ok(())
    }))),
    None,
    ConnectionPolicy {
        min_security_level: SecurityLevel::None,
        authorization_required: false,
        auto_accept: true,
    },
)?;

// Disconnect when done
l2cap_manager.disconnect(cid)?;
```

## Specification References

This implementation follows these sections of the Bluetooth Core Specification v5.2:

- **Vol 3, Part A**: L2CAP Specification
  - Section 2: General Operation
  - Section 3: Data Packet Format
  - Section 4: Signaling Packet Formats
  - Section 7: L2CAP for LE

- **Channel Identifiers**: https://www.bluetooth.com/specifications/assigned-numbers/logical-link-control/
- **Protocol/Service Multiplexers**: https://www.bluetooth.com/specifications/assigned-numbers/service-discovery/