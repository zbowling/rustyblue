# Attribute Protocol (ATT)

The Attribute Protocol (ATT) is a client/server protocol that allows devices to discover, read, and write attributes on a peer device. It is the foundation for the Generic Attribute Profile (GATT).

## Overview

The ATT module in RustyBlue implements:

- **ATT Client**: Sends requests to the ATT server to discover, read, and write attributes
- **ATT Server**: Maintains a database of attributes and responds to client requests
- **Attribute Database**: Stores and manages attributes
- **Packet Encoding/Decoding**: Serialization and parsing of ATT protocol messages

## Architecture

ATT consists of a client/server architecture:

- **Server**: Maintains a database of attributes (GATT services, characteristics, etc.)
- **Client**: Sends requests to the server to discover, read, and write attributes

## Components

### AttClient

The `AttClient` class implements the client side of the ATT protocol:

```rust
// Create an ATT client
let att_client = AttClient::new(remote_addr, l2cap_manager.clone());

// Connect to remote device
att_client.connect(hci_handle)?;

// Exchange MTU
let mtu = att_client.exchange_mtu(512)?;
println!("Negotiated MTU: {}", mtu);

// Discover services
let services = att_client.read_by_group_type(
    0x0001,           // Start handle
    0xFFFF,           // End handle
    &PRIMARY_SERVICE_UUID.into()  // Service UUID
)?;

// Read a characteristic value
let value = att_client.read(handle)?;
```

### AttServer

The `AttServer` class implements the server side of the ATT protocol:

```rust
// Create an attribute database
let database = Arc::new(AttributeDatabase::new());

// Create an ATT server
let att_server = AttServer::new(l2cap_manager.clone(), database.clone());

// Configure the server
att_server.set_config(AttServerConfig {
    mtu: 512,
    security_level: SecurityLevel::EncryptionWithAuthentication,
});

// Start the server
att_server.start()?;

// Send a notification to a client
att_server.send_notification(client_addr, handle, &value)?;
```

### AttributeDatabase

The `AttributeDatabase` manages a collection of attributes:

```rust
// Add a service to the database
let service_handle = database.add_attribute_with_next_handle(
    PRIMARY_SERVICE_UUID.into(),
    service_uuid.as_bytes().to_vec(),
    AttPermissions::read_only()
)?;

// Add a characteristic to the database
let char_decl_handle = database.add_attribute_with_next_handle(
    CHARACTERISTIC_UUID.into(),
    char_declaration.to_vec(),
    AttPermissions::read_only()
)?;

// Register a read callback
database.register_read_callback(
    value_handle,
    Arc::new(move |handle| {
        // Generate or fetch the value when read
        Ok(some_value.to_vec())
    })
)?;

// Register a write callback
database.register_write_callback(
    value_handle,
    Arc::new(move |handle, value| {
        // Process the write
        println!("Received write: {:?}", value);
        Ok(())
    })
)?;
```

## ATT Protocol

### PDU Types

The ATT protocol defines several Protocol Data Unit (PDU) types:

- **Request**: Sent by the client to the server (requires response)
- **Response**: Sent by the server in response to a request
- **Command**: Sent by the client to the server (no response)
- **Notification**: Sent by the server to the client (no confirmation)
- **Indication**: Sent by the server to the client (requires confirmation)
- **Confirmation**: Sent by the client in response to an indication

### Operations

ATT supports these key operations:

- **Exchange MTU**: Negotiate the maximum transmission unit size
- **Find Information**: Discover attribute types (UUIDs)
- **Find By Type Value**: Find attributes by type and value
- **Read By Type**: Read attributes by type
- **Read**: Read an attribute value
- **Write**: Write an attribute value
- **Notifications/Indications**: Server-initiated updates

## Attribute Structure

Each attribute in ATT has:

- **Handle**: A 16-bit identifier (unique within the server)
- **Type**: A UUID that identifies the attribute type
- **Value**: The data content of the attribute
- **Permissions**: Access rules (read, write, encrypt, authenticate)

## Security

ATT supports several security levels:

- **None**: No encryption or authentication
- **EncryptionOnly**: Encrypted link without authentication
- **EncryptionWithAuthentication**: Encrypted and authenticated link
- **SecureConnections**: Secure Connections with encryption and authentication

Each attribute can specify its required security level through permissions.

## Usage Examples

### Reading a Characteristic Value

```rust
// Client-side: Read a characteristic value
let value = att_client.read(handle)?;
println!("Characteristic value: {:?}", value);
```

### Writing a Characteristic Value

```rust
// Client-side: Write a characteristic value
att_client.write(handle, &value)?;
```

### Sending Notifications

```rust
// Server-side: Send a notification to a client
att_server.send_notification(client_addr, handle, &updated_value)?;
```

### Handling Notifications

```rust
// Client-side: Set up notification handling
att_client.set_notification_callback(|handle, value| {
    println!("Notification for handle 0x{:04X}: {:?}", handle, value);
    Ok(())
});
```

## Limitations

Current limitations of the ATT implementation:

- **Signed Write**: Not yet implemented
- **Connection Parameter Updates**: Not tightly integrated with connection parameter updates
- **Multiple Value Notifications**: Not yet supported
- **Comprehensive Testing**: Needs more extensive testing

## Future Work

Planned improvements for the ATT implementation:

1. Add support for signed writes
2. Add comprehensive permission validation
3. Improve authentication and authorization handling
4. Add support for multiple value notifications
5. Optimize attribute database operations for large databases
6. Add persistent storage for attribute values