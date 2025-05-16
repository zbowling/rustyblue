# RustyBlue

A Rust library for Bluetooth HCI (Host Controller Interface) communication and Bluetooth Low Energy (BLE) operations on Linux systems.

## Features

- Bluetooth HCI communication for low-level access to Bluetooth controllers
- GATT (Generic Attribute Profile) client and server implementation
- L2CAP (Logical Link Control and Adaptation Protocol) support
- ATT (Attribute Protocol) client and server implementation
- GAP (Generic Access Profile) device management
- SMP (Security Manager Protocol) for secure connections
- SDP (Service Discovery Protocol) for Bluetooth Classic

## Architecture

RustyBlue is structured according to the Bluetooth protocol stack:

### HCI Layer
The Host Controller Interface provides direct access to Bluetooth controllers, handling commands, events and data packets.
- Based on Bluetooth Core Specification v5.2, Vol 2, Part E

### L2CAP Layer
Logical Link Control and Adaptation Protocol provides multiplexing, segmentation/reassembly, flow control and channel management.
- Based on Bluetooth Core Specification v5.2, Vol 3, Part A

### ATT Layer
Attribute Protocol provides the foundation for discovering, reading, and writing attributes on a device.
- Based on Bluetooth Core Specification v5.2, Vol 3, Part F

### GATT Layer
Generic Attribute Profile provides a framework for service discovery and interaction.
- Based on Bluetooth Core Specification v5.2, Vol 3, Part G

### GAP Layer
Generic Access Profile provides connection management and device discovery.
- Based on Bluetooth Core Specification v5.2, Vol 3, Part C

### SMP Layer
Security Manager Protocol implements encryption and authentication mechanisms.
- Based on Bluetooth Core Specification v5.2, Vol 3, Part H

## Requirements

- Linux operating system
- Bluetooth adapter
- Root privileges (for opening raw HCI sockets)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rustyblue = "0.1.0"
```

## Usage

### Opening an HCI Socket

```rust
use rustyblue::HciSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open an HCI socket for the first Bluetooth adapter (device ID 0)
    let socket = HciSocket::open(0)?;
    
    // The socket will be automatically closed when it goes out of scope
    
    Ok(())
}
```

### Scanning for Bluetooth LE Devices

```rust
use rustyblue::{GapAdapter, scan_le};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a GAP adapter
    let mut adapter = GapAdapter::new(0)?;
    
    // Start device discovery
    adapter.start_discovery(Box::new(|device| {
        println!("Found device: {:?} (RSSI: {:?})", device.addr, device.rssi);
        if let Some(name) = &device.name {
            println!("  Name: {}", name);
        }
    }))?;
    
    // Process events for 5 seconds
    adapter.process_events(Some(Duration::from_secs(5)))?;
    
    // Stop discovery
    adapter.stop_discovery()?;
    
    Ok(())
}
```

### GATT Client Operations

```rust
use rustyblue::{GattClient, HciSocket, L2capManager};
use std::sync::Arc;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open HCI socket
    let socket = HciSocket::open(0)?;
    
    // Create L2CAP manager
    let l2cap_manager = Arc::new(L2capManager::new(ConnectionType::LE));
    
    // Create GATT client
    let mut client = GattClient::new(socket, l2cap_manager);
    
    // Connect to a device (example Bluetooth address)
    let addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    client.connect(addr, 0)?; // 0 = public address type
    
    // Process events until connected
    while client.connection_state() != ConnectionState::Connected {
        client.process_events(Some(Duration::from_millis(100)))?;
    }
    
    // Discover services
    let services = client.discover_services()?;
    
    for service in &services {
        println!("Service: {}", service.uuid);
        
        // Discover characteristics for this service
        let characteristics = client.discover_characteristics(service)?;
        
        for characteristic in &characteristics {
            println!("  Characteristic: {}", characteristic.uuid);
            
            // If characteristic is readable
            if characteristic.properties.can_read() {
                // Read the value
                let value = client.read_characteristic(characteristic)?;
                println!("    Value: {:?}", value);
            }
        }
    }
    
    // Disconnect
    client.disconnect()?;
    
    Ok(())
}
```

## References

- [Bluetooth Core Specification v5.2](https://www.bluetooth.com/specifications/bluetooth-core-specification/)
- [Bluetooth SIG Assigned Numbers](https://www.bluetooth.com/specifications/assigned-numbers/)
- [Bluetooth LE Security](https://www.bluetooth.com/blog/bluetooth-low-energy-it-starts-with-advertising/)
- [Introduction to Bluetooth Low Energy](https://learn.adafruit.com/introduction-to-bluetooth-low-energy)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 