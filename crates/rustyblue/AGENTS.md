# RustyBlue Architecture

## Overview

RustyBlue is a Rust library for Bluetooth HCI (Host Controller Interface) communication, focusing on providing a safe and ergonomic API for Bluetooth Low Energy (BLE) development. The library is structured into several key components that handle different layers of the Bluetooth protocol stack.

## Core Components

### HCI Layer (`hci/`)
- Raw HCI socket communication
- Command and event handling
- ACL (Asynchronous Connection-Less) data handling
- Low-level packet parsing and construction

### GAP Layer (`gap/`)
- Device discovery and scanning
- Connection management
- Address handling
- Basic device information

### GATT Layer (`gatt/`)
- Service and characteristic management
- Client and server implementations
- Attribute protocol handling
- UUID management

### L2CAP Layer (`l2cap/`)
- Logical Link Control and Adaptation Protocol
- Channel management
- Connection-oriented and connectionless channels
- Segmentation and reassembly

### ATT Layer (`att/`)
- Attribute Protocol implementation
- Attribute database management
- Client and server roles
- Error handling

### SMP Layer (`smp/`)
- Security Manager Protocol
- Pairing and bonding
- Key distribution
- Security level management

### SDP Layer (`sdp/`)
- Service Discovery Protocol
- Service record management
- Client and server implementations

## Development Status

### Current Focus
- HCI socket implementation
- Basic command/event handling
- ACL data handling

### Planned Features
- Complete GATT client/server implementation
- Enhanced security features
- Cross-platform support
- Better error handling and recovery
- Comprehensive documentation and examples

## Contributing

When contributing to RustyBlue, please follow these guidelines:

1. Focus on one component at a time
2. Ensure all code compiles before submitting
3. Add appropriate tests for new functionality
4. Update documentation as needed
5. Follow Rust best practices and idioms

## Building and Testing

The library requires:
- Rust 1.70 or later
- Linux operating system (for HCI socket support)
- Root privileges for HCI operations
- Bluetooth adapter hardware

To build:
```bash
cargo build
```

To run tests:
```bash
sudo cargo test  # Requires root for HCI tests
``` 