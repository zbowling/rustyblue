# L2CAP (Logical Link Control and Adaptation Protocol)

The L2CAP layer sits on top of the HCI (Host Controller Interface) layer and provides a multiplexing layer that allows multiple protocols to share the physical Bluetooth connection. This README provides an overview of the L2CAP implementation in RustyBlue.

## Overview

L2CAP provides the following services to upper layers:

- **Protocol/Service Multiplexing**: Routes data to the appropriate upper layer protocol
- **Segmentation and Reassembly**: Breaks large packets into smaller segments for transmission
- **Flow Control**: Prevents buffer overflows on receiving devices
- **Error Control**: Ensures reliable delivery of data with retransmission if needed
- **Quality of Service (QoS)**: Provides configurable service quality options

## Components

The L2CAP implementation in RustyBlue consists of the following key components:

### L2capManager

The central component that manages all L2CAP operations:
- Channel creation and management
- PSM registration and lookup
- Connection establishment and teardown
- Signaling message handling
- Data routing between channels

```rust
let l2cap_manager = L2capManager::new(ConnectionType::LE);

// Register a PSM for an upper layer protocol
l2cap_manager.register_psm(
    PSM::SDP,
    Some(data_callback),
    Some(event_callback),
    ConnectionPolicy {
        min_security_level: SecurityLevel::None,
        authorization_required: false,
        auto_accept: true,
    }
)?;

// Connect to a remote device
let channel_id = l2cap_manager.connect(PSM::RFCOMM, hci_handle)?;

// Send data on a channel
l2cap_manager.send_data(channel_id, &data)?;
```

### L2capChannel

Represents a logical connection between two devices:
- Handles channel state management (open, closed, connecting, etc.)
- Processes incoming data
- Implements segmentation and reassembly
- Supports different channel modes (Basic, Retransmission, Streaming)
- Handles LE Credit-based flow control

### Signaling Messages

L2CAP uses signaling messages for connection management:
- Connection requests and responses
- Configuration requests and responses
- Disconnection requests and responses
- Information requests and responses
- LE credit-based connection management

### Protocol/Service Multiplexer (PSM)

Identifies upper layer protocols:
- Fixed PSMs for standard protocols (SDP, RFCOMM, etc.)
- Dynamic PSMs for custom protocols

## Features

The L2CAP implementation includes:

- **Connection-oriented channels**: For reliable data transfer
- **Connectionless channels**: For broadcast/multicast scenarios
- **Retransmission and Flow Control**: Enhanced reliability modes
- **LE-specific features**: Credit-based flow control, connection parameter updates
- **Fixed channels**: Pre-defined channels for specific protocols (ATT, SMP, etc.)
- **Dynamic channels**: Created on-demand for upper layer protocols

## Usage Examples

### Establishing a Connection

```rust
// Create the L2CAP manager
let l2cap_manager = L2capManager::new(ConnectionType::Classic);

// Register a data callback
let data_callback = |data: &[u8]| -> L2capResult<()> {
    println!("Received data: {:?}", data);
    Ok(())
};

// Register an event callback
let event_callback = |event: ChannelEvent| -> L2capResult<()> {
    match event {
        ChannelEvent::Connected { cid, psm } => {
            println!("Channel connected: CID={}, PSM={:?}", cid, psm);
        },
        ChannelEvent::Disconnected { cid, psm, reason } => {
            println!("Channel disconnected: CID={}, PSM={:?}, Reason={}", cid, psm, reason);
        },
        _ => {}
    }
    Ok(())
};

// Register a PSM
l2cap_manager.register_psm(
    PSM::RFCOMM,
    Some(Arc::new(Mutex::new(data_callback))),
    Some(Arc::new(Mutex::new(event_callback))),
    ConnectionPolicy {
        min_security_level: SecurityLevel::None,
        authorization_required: false,
        auto_accept: true,
    }
)?;

// Connect to a remote device
let hci_handle = 0x0042; // Obtained from HCI layer
let channel_id = l2cap_manager.connect(PSM::RFCOMM, hci_handle)?;

// Send data
l2cap_manager.send_data(channel_id, b"Hello, Bluetooth!")?;

// Disconnect when done
l2cap_manager.disconnect(channel_id)?;
```

### Handling Incoming Connections

```rust
// Set a global event callback to handle incoming connections
l2cap_manager.set_global_event_callback(|event| -> L2capResult<()> {
    match event {
        ChannelEvent::ConnectionRequest { identifier, psm, source_cid } => {
            println!("Incoming connection request: PSM={:?}, Source CID={}", psm, source_cid);
            
            // Accept the connection (in a real implementation, you'd track the local CID)
            let local_cid = 0x0040; // This would be returned by l2cap_manager
            l2cap_manager.accept_connection(identifier, local_cid, hci_handle)?;
        },
        _ => {}
    }
    Ok(())
});
```

## Limitations

Current limitations of the L2CAP implementation:

1. **Partial Implementation**: Some advanced features like streaming mode are not fully implemented
2. **Limited Testing**: More extensive testing is needed for robustness
3. **No Flush Timeout Support**: The implementation doesn't fully utilize flush timeouts
4. **Security Integration**: Security manager integration is still pending
5. **Connection Parameter Updates**: Full HCI integration for LE parameter updates is needed

## Future Work

Planned improvements for the L2CAP implementation:

1. Complete implementation of Enhanced Retransmission Mode
2. Add proper support for MTU negotiation
3. Improve error handling and recovery
4. Implement comprehensive unit and integration tests
5. Better integration with the Security Manager
6. Add support for L2CAP Extended Features
7. Implement Enhanced Credit-Based Flow Control