# GATT (Generic Attribute Profile) Implementation

This module provides an implementation of the Bluetooth GATT protocol, which defines how devices discover, read, write, and observe attribute values over a Bluetooth Low Energy (BLE) connection.

## Overview

The GATT implementation consists of the following components:

- **client.rs**: GATT client implementation for connecting to and interacting with GATT servers
- **server.rs**: GATT server implementation for providing services to connected clients
- **types.rs**: Common data types for GATT operations
- **tests.rs**: Unit tests for GATT functionality

## Components

### GattClient (client.rs)

The `GattClient` provides functionality for connecting to and interacting with GATT servers:

- Connection establishment and management
- Service discovery
- Characteristic discovery and interaction
- Connection state tracking and event handling
- Notification and indication support

```rust
// Example: Creating a GATT client and connecting to a device
let socket = HciSocket::open(0)?;
let l2cap_manager = Arc::new(L2capManager::new(socket.clone()));
let mut client = GattClient::new(socket, l2cap_manager);

// Connect to a device
client.connect([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x00)?;

// Wait for connection events
client.process_events(Some(Duration::from_secs(5)))?;

// Discover services if connected
if client.connection_state() == ConnectionState::Connected {
    let services = client.discover_services()?;
    // ...
}
```

### GattServer (server.rs)

The `GattServer` provides functionality for hosting GATT services for clients to connect to:

- Service, characteristic, and descriptor creation and management
- Read and write request handling
- Notification and indication support
- Permission control for attributes
- Client connection management

```rust
// Example: Creating a GATT server with a custom service
let socket = HciSocket::open(0)?;
let l2cap_manager = Arc::new(L2capManager::new(socket.clone()));
let database = Arc::new(AttributeDatabase::new());
let att_server = Arc::new(AttServer::new(l2cap_manager.clone(), database.clone()));
let gatt_server = GattServer::new(att_server, database);

// Configure and start the server
gatt_server.set_config(GattServerConfig {
    max_mtu: 517,
    security_level: SecurityLevel::None,
});
gatt_server.start()?;

// Add a service
let service_uuid = Uuid::from_u16(0x180F); // Battery Service
let service_handle = gatt_server.add_service(service_uuid, true)?;

// Add a characteristic
let char_uuid = Uuid::from_u16(0x2A19); // Battery Level
let properties = CharacteristicProperty(CharacteristicProperty::READ | CharacteristicProperty::NOTIFY);
let permissions = AttPermissions::read_only();
let char_handle = gatt_server.add_characteristic(
    service_handle, 
    char_uuid, 
    properties,
    permissions,
    vec![100], // 100% battery
)?;

// Add a CCCD to enable notifications
gatt_server.add_cccd(char_handle)?;
```

### GATT Types (types.rs)

Defines common data structures used in GATT operations:

- **Uuid**: 16-bit, 32-bit, and 128-bit UUID representations
- **Service**: Representation of a GATT service
- **Characteristic**: Representation of a GATT characteristic
- **CharacteristicProperty**: Flags for characteristic capabilities (read, write, notify, etc.)

```rust
// Example: Working with services and characteristics
for service in services {
    println!("Service: {}", service.uuid);
    let characteristics = client.discover_characteristics(&service)?;
    
    for characteristic in characteristics {
        if characteristic.properties.can_read() {
            let value = client.read_characteristic(&characteristic)?;
            println!("Characteristic value: {:?}", value);
        }
        
        if characteristic.properties.can_notify() {
            client.enable_notifications(&characteristic)?;
        }
    }
}
```

### Connection Events

The client includes event handling for connection-related events:

- **LeConnectionComplete**: Parsed event data for connection establishment
- **DisconnectionComplete**: Parsed event data for connection termination
- **ConnectionCallback**: Callback type for monitoring connection state changes

## Current Capabilities

### Client Capabilities
- Connection establishment and termination
- Connection state tracking
- Event handling
- Callback-based connection monitoring
- Finding services and characteristics by UUID
- Characteristic read/write operations
- Support for notifications and indications
- Support for characteristic descriptors
- ATT MTU negotiation

### Server Capabilities
- Service, characteristic, and descriptor creation
- Handling of client read/write requests
- Support for sending notifications and indications
- Attribute permission management
- Client characteristic configuration (CCCD) handling
- Attribute value updates

## Implementation Details

- The GATT layer is built on top of the Attribute Protocol (ATT) layer
- Service discovery uses ATT Read By Group Type operations
- Characteristic discovery uses ATT Read By Type operations
- Notifications and indications use ATT Handle Value Notification/Indication
- The server uses an AttributeDatabase for storing attribute values
- Permissions are enforced at the ATT layer

## Usage Examples

### GATT Client Example

```rust
// Initialize GATT client
let socket = HciSocket::open(0)?;
let l2cap_manager = Arc::new(L2capManager::new(socket.clone()));
let mut client = GattClient::new(socket, l2cap_manager);

// Set up connection state callback
client.set_connection_callback(Box::new(|state, handle| {
    println!("Connection state changed: {:?}, handle: {}", state, handle);
}));

// Set up notification callback
client.set_notification_callback(|handle, value| {
    println!("Notification received, handle: {}, value: {:?}", handle, value);
    Ok(())
});

// Connect to a device
println!("Connecting to device...");
client.connect([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], 0x00)?;

// Process events to handle connection
println!("Waiting for connection...");
for _ in 0..10 {
    client.process_events(Some(Duration::from_millis(500)))?;
    if client.connection_state() == ConnectionState::Connected {
        break;
    }
}

// If connected, discover services
if client.connection_state() == ConnectionState::Connected {
    println!("Connected! Discovering services...");
    let services = client.discover_services()?;
    
    // Find a specific service by UUID
    let heart_rate_uuid = Uuid::from_u16(0x180D); // Heart Rate service
    if let Some(service) = client.find_service(&heart_rate_uuid) {
        println!("Found Heart Rate service!");
        
        // Discover characteristics
        let characteristics = client.discover_characteristics(&service)?;
        
        // Find Heart Rate Measurement characteristic
        let hr_measurement_uuid = Uuid::from_u16(0x2A37);
        if let Some(characteristic) = client.find_characteristic(&service, &hr_measurement_uuid) {
            // Enable notifications for the characteristic
            client.enable_notifications(&characteristic)?;
            println!("Enabled notifications for heart rate measurement");
            
            // Continue processing events to receive notifications
            for _ in 0..30 {
                client.process_events(Some(Duration::from_secs(1)))?;
            }
        }
    }
    
    // Disconnect when done
    client.disconnect()?;
}
```

### GATT Server Example

```rust
// Initialize GATT server
let socket = HciSocket::open(0)?;
let l2cap_manager = Arc::new(L2capManager::new(socket.clone()));
let database = Arc::new(AttributeDatabase::new());
let att_server = Arc::new(AttServer::new(l2cap_manager.clone(), database.clone()));
let gatt_server = GattServer::new(att_server, database);

// Start the server
gatt_server.start()?;

// Add a battery service
let battery_service_uuid = Uuid::from_u16(0x180F);
let service_handle = gatt_server.add_service(battery_service_uuid, true)?;

// Add battery level characteristic
let battery_level_uuid = Uuid::from_u16(0x2A19);
let properties = CharacteristicProperty(CharacteristicProperty::READ | CharacteristicProperty::NOTIFY);
let permissions = AttPermissions::read_only();
let battery_level_handle = gatt_server.add_characteristic(
    service_handle,
    battery_level_uuid,
    properties,
    permissions,
    vec![100], // 100% battery
)?;

// Add CCCD for notifications
gatt_server.add_cccd(battery_level_handle)?;

// Set up advertising to make the server discoverable
// (advertising setup code here)

// Main server loop
let mut battery_level = 100;
loop {
    // Process events
    match socket.read_event_timeout(Some(Duration::from_secs(1))) {
        Ok(event) => {
            // Handle connection/disconnection events
        },
        Err(_) => {
            // Update battery level and notify clients
            if battery_level > 0 {
                battery_level -= 1;
                let _ = gatt_server.update_characteristic(
                    battery_level_handle,
                    &[battery_level],
                    true,  // Notify
                    false, // Don't indicate
                );
                println!("Updated battery level: {}", battery_level);
            }
            
            // Sleep before next update
            std::thread::sleep(Duration::from_secs(60));
        }
    }
}
```

## Development and Testing

The implementation includes unit tests for connection event parsing and other functionality. Run the tests with:

```bash
cargo test --package rustyblue --lib -- gatt::tests
```