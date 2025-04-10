# HCI (Host Controller Interface) Implementation

This module provides a Rust implementation of the Bluetooth HCI protocol, which is the primary interface for communication between the host system and the Bluetooth controller hardware.

## Overview

The HCI implementation is organized into several components:

- **socket.rs**: Low-level socket communication with Bluetooth controllers
- **packet.rs**: Data structures and serialization for HCI commands and events
- **constants.rs**: Definition of HCI protocol constants
- **tests.rs**: Unit tests for HCI functionality

## Components

### HciSocket (socket.rs)

The `HciSocket` provides direct communication with Bluetooth controllers through the operating system's HCI socket interface:

- Opening raw HCI sockets on specific device interfaces
- Sending HCI commands to the controller
- Receiving HCI events from the controller with timeout support
- Proper resource management with automatic socket cleanup

```rust
// Example: Opening an HCI socket and sending a command
let socket = HciSocket::open(0)?; // Open the first Bluetooth adapter
socket.send_command(&HciCommand::Reset)?; // Send a Reset command
```

### HciCommand (packet.rs)

Represents various HCI commands that can be sent to the controller:

- High-level command representations with appropriate parameters
- Common commands like Reset, Set Scan Parameters, etc.
- Raw commands for custom or less common operations
- Serialization to binary format for transmission

```rust
// Example: Creating a scan command
let cmd = HciCommand::LeSetScanParameters {
    scan_type: 0x01,           // Active scanning
    scan_interval: 0x0010,     // 10ms interval
    scan_window: 0x0010,       // 10ms window
    own_address_type: 0x00,    // Public address
    filter_policy: 0x00,       // No filtering
};
```

### HciEvent (packet.rs)

Represents events received from the controller:

- Parsing of raw event data into structured events
- Event parameter extraction
- Helper methods for checking event types and status
- Special handling for command completion events

```rust
// Example: Handling an event
if event.is_command_complete(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS) {
    let status = event.get_status();
    if status == 0 {
        // Command succeeded
    }
}
```

### LeAdvertisingReport (packet.rs)

Specialized event structure for handling Bluetooth LE advertising reports:

- Parsing of advertising report data
- Multiple report handling in a single event
- Extraction of address, data, and RSSI information

## Constants (constants.rs)

Defines constants used throughout the HCI protocol:

- Packet types (Command, Event, etc.)
- Operation codes (OGF and OCF values)
- Event codes
- Parameter limits
- Status codes
- Feature bits

## Current Capabilities

- Socket creation and management
- Command creation and transmission
- Event reception and parsing
- LE advertising report handling
- Timeout-based event handling
- Basic error handling

## Limitations & Future Work

1. **Missing HCI Commands**: Not all possible HCI commands are explicitly implemented. Currently supported are basic LE scanning, connection, and general controller management.

2. **ACL Data Packets**: ACL data packet handling is not fully implemented yet, which is necessary for higher-level protocols like L2CAP, SDP, and GATT.

3. **Synchronous Connections**: SCO/eSCO connections for audio are not implemented.

4. **Enhanced Features**: Enhanced/extended advertising and scanning features from Bluetooth 5.0+ are not yet supported.

5. **Multiple Adapter Support**: Better support for managing multiple Bluetooth adapters simultaneously.

6. **Cross-Platform Compatibility**: Current implementation focuses on Unix-like platforms.

7. **Isochronous Channels**: Bluetooth LE Audio support (added in Bluetooth 5.2) is not implemented.

## Usage Examples

```rust
// Initialize the HCI socket for the first adapter
let socket = HciSocket::open(0)?;

// Reset the controller
socket.send_command(&HciCommand::Reset)?;
let event = socket.read_event()?;
assert!(event.is_command_complete(OGF_HOST_CTL, OCF_RESET));

// Set up LE scanning
socket.send_command(&HciCommand::LeSetScanParameters {
    scan_type: 0x01,
    scan_interval: 0x0010,
    scan_window: 0x0010,
    own_address_type: 0x00,
    filter_policy: 0x00,
})?;

// Enable scanning
socket.send_command(&HciCommand::LeSetScanEnable {
    enable: true,
    filter_duplicates: true,
})?;

// Process received events
loop {
    match socket.read_event_timeout(Some(Duration::from_secs(1))) {
        Ok(event) => {
            if event.event_code == EVT_LE_META_EVENT && !event.parameters.is_empty() {
                if event.parameters[0] == EVT_LE_ADVERTISING_REPORT {
                    let reports = LeAdvertisingReport::parse_from_event(&event)?;
                    for report in reports {
                        println!("Device: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, RSSI: {}",
                            report.address[5], report.address[4], report.address[3],
                            report.address[2], report.address[1], report.address[0],
                            report.rssi);
                    }
                }
            }
        },
        Err(_) => break,
    }
}

// Disable scanning
socket.send_command(&HciCommand::LeSetScanEnable {
    enable: false,
    filter_duplicates: false,
})?;
```

## Development and Testing

The implementation includes unit tests for the packet serialization, parsing, and event handling. Run the tests with:

```bash
cargo test --package rustyblue --lib -- hci::tests
```