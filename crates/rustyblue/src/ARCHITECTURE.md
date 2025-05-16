# RustyBlue Architecture

This document describes the architecture of the RustyBlue Bluetooth protocol stack.

## Overview

RustyBlue is a Rust implementation of the Bluetooth protocol stack, following the layered architecture defined in the Bluetooth Core Specification v5.2. The main components are:

```
+-------------------+
|     Applications  |
+-------------------+
|  GATT  |   GAP    |
+-------------------+
|  ATT   |   SMP    |
+-------------------+
|        L2CAP      |
+-------------------+
|         HCI       |
+-------------------+
|  Bluetooth Radio  |
+-------------------+
```

Each layer provides services to the layer above it and uses services from the layer below it.

## Layer Descriptions

### HCI (Host Controller Interface)

The HCI layer provides direct communication with the Bluetooth controller:
- Socket abstraction for sending commands and receiving events
- Command building and parsing
- Event handling
- ACL, SCO, and ISO data packet handling

Key files:
- `src/hci/socket.rs`: HCI socket implementation
- `src/hci/command.rs`: HCI command building
- `src/hci/event.rs`: HCI event parsing
- `src/hci/constants.rs`: HCI constants from the specification

### L2CAP (Logical Link Control and Adaptation Protocol)

The L2CAP layer manages logical connections between devices:
- Channel management
- Multiplexing between higher layers
- Segmentation and reassembly
- Flow control
- QoS (Quality of Service)

Key files:
- `src/l2cap/core.rs`: L2CAP manager implementation
- `src/l2cap/channel.rs`: L2CAP channel implementation
- `src/l2cap/packet.rs`: L2CAP packet format and parsing
- `src/l2cap/signaling.rs`: L2CAP signaling commands
- `src/l2cap/types.rs`: L2CAP data types
- `src/l2cap/constants.rs`: L2CAP constants from the specification

### ATT (Attribute Protocol)

The ATT layer provides the foundation for attribute access:
- Client/server communication
- Attribute operations (read, write, notify, indicate)
- Error handling
- Attribute database management

Key files:
- `src/att/client.rs`: ATT client implementation
- `src/att/server.rs`: ATT server implementation
- `src/att/database.rs`: Attribute database implementation
- `src/att/types.rs`: ATT data types and packet formats
- `src/att/error.rs`: ATT error handling
- `src/att/constants.rs`: ATT constants from the specification

### GATT (Generic Attribute Profile)

The GATT layer provides a framework for service discovery and interaction:
- Service discovery
- Characteristic operations
- Descriptor handling
- High-level GATT operations

Key files:
- `src/gatt/client.rs`: GATT client implementation
- `src/gatt/server.rs`: GATT server implementation
- `src/gatt/types.rs`: GATT data types (Service, Characteristic, Descriptor)

### GAP (Generic Access Profile)

The GAP layer manages device discovery and connection:
- Device scanning
- Advertising
- Connection management
- Security setting

Key files:
- `src/gap/adapter.rs`: GAP adapter implementation
- `src/gap/types.rs`: GAP data types (Device, BdAddr)
- `src/gap/constants.rs`: GAP constants from the specification

### SMP (Security Manager Protocol)

The SMP layer handles security aspects:
- Pairing
- Bonding
- Key distribution
- Encryption

Key files:
- `src/smp/manager.rs`: SMP manager implementation
- `src/smp/pairing.rs`: Pairing procedures
- `src/smp/keys.rs`: Key management
- `src/smp/crypto.rs`: Cryptographic operations
- `src/smp/types.rs`: SMP data types

### SDP (Service Discovery Protocol)

The SDP layer is used in Bluetooth Classic for service discovery:
- Service record handling
- Service queries
- Protocol handling

Key files:
- `src/sdp/client.rs`: SDP client implementation
- `src/sdp/server.rs`: SDP server implementation
- `src/sdp/protocol.rs`: SDP protocol implementation
- `src/sdp/types.rs`: SDP data types

## Data Flow

1. **Outgoing data path**:
   - Application → GATT/GAP → ATT/SMP → L2CAP → HCI → Controller

2. **Incoming data path**:
   - Controller → HCI → L2CAP → ATT/SMP → GATT/GAP → Application

## Design Principles

1. **Safety**: Rust's ownership model helps prevent memory and concurrency issues
2. **Modularity**: Each layer is self-contained with clear interfaces
3. **Extensibility**: New profiles can be added without modifying core components
4. **Correctness**: Follows the Bluetooth specification closely
5. **Performance**: Minimizes overhead in critical paths

## Dependency Graph

```
GATT Client → ATT Client → L2CAP → HCI
      ↑           ↑          ↑       ↑
      |           |          |       |
GATT Server → ATT Server     |       |
                             |       |
SMP →--------------------------       |
                                     |
GAP →------------------------------------
```

## References

- [Bluetooth Core Specification v5.2](https://www.bluetooth.com/specifications/bluetooth-core-specification/)
- [Bluetooth SIG Assigned Numbers](https://www.bluetooth.com/specifications/assigned-numbers/) 