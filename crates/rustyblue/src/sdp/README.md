# SDP (Service Discovery Protocol) Implementation

This module provides an implementation of the Bluetooth Service Discovery Protocol (SDP), which allows Bluetooth devices to discover available services and their characteristics.

## Overview

The SDP implementation is organized into several components:

- **types.rs**: Data structures for SDP records, UUIDs, and attributes
- **protocol.rs**: SDP protocol message encoding and decoding
- **client.rs**: SDP client implementation for querying remote SDP servers
- **server.rs**: SDP server implementation for hosting service records

## Components

### SDP Types (types.rs)

Defines the core data structures used in SDP operations:

- **ServiceRecord**: Represents a complete service record with attributes
- **Uuid**: 16-bit, 32-bit, and 128-bit UUID representations
- **DataElement**: SDP data element types (integers, strings, UUIDs, etc.)
- **AttributeId**: Common SDP attribute identifiers
- **SdpPdu**: SDP protocol data unit types

```rust
// Example: Creating a service record
let service_record = ServiceRecord {
    service_class_id_list: vec![Uuid::Uuid16(0x1101)],  // Serial Port Profile
    attributes: HashMap::new(),
    handle: 0x10000,
};
```

### SDP Protocol (protocol.rs)

Handles the encoding and decoding of SDP protocol messages:

- **SdpPacket**: Representation of SDP PDUs
- **encode_service_search_request**: Creates service search request packets
- **decode_data_element**: Parses SDP data elements from binary format

```rust
// Example: Creating and serializing an SDP packet
let packet = SdpPacket::new(
    SdpPdu::ServiceSearchRequest,
    0x0001,  // Transaction ID
    parameters
);
let raw_data = packet.serialize();
```

### SDP Client (client.rs)

Implements the client-side functionality for discovering services:

- Connecting to remote SDP servers
- Discovering services by UUID
- Retrieving service attributes
- Combined service search and attribute retrieval

```rust
// Example: Discovering services
let mut client = SdpClient::new();
client.connect()?;

// Search for the Serial Port Profile
let spp_uuid = Uuid::Uuid16(0x1101);
let services = client.discover_services(&[spp_uuid])?;

// Get attributes for a specific service
let handle = services[0].handle;
let attributes = client.get_service_attributes(handle, &[0x0100])?;
```

### SDP Server (server.rs)

Implements the server-side functionality for hosting service records:

- Registering service records
- Handling SDP requests (search, attribute retrieval)
- Response generation

```rust
// Example: Hosting an SDP server
let mut server = SdpServer::new();

// Register a Serial Port service
let service = ServiceRecord {
    service_class_id_list: vec![Uuid::Uuid16(0x1101)],
    attributes: attributes_map,
    handle: 0,  // Server will assign a handle
};
let handle = server.register_service(service);

// Server would then handle incoming requests
let response = server.handle_request(&incoming_request)?;
```

## Current Capabilities

- Basic SDP data structures
- Service record representation
- Protocol message encoding/decoding
- Service discovery client framework
- Service hosting server framework

## Limitations & Future Work

1. **L2CAP Integration**: The SDP implementation requires integration with L2CAP for actual communication with remote devices. Currently, it only provides the protocol handling without the transport layer.

2. **Attribute Value Parsing**: More complete parsing of attribute values, especially complex types like service record handles list and protocol descriptor list.

3. **Service Record Browsing**: Support for browsing groups is not fully implemented.

4. **Data Element Encoding**: While basic data element decoding is implemented, encoding for all types is not complete.

5. **Service Registration API**: A more user-friendly API for registering common service types.

6. **Service Record Validation**: Validation of service records against Bluetooth SIG specifications.

7. **Error Response Handling**: More detailed error responses and recovery mechanisms.

8. **Continuation State Handling**: Support for receiving large responses in multiple fragments.

9. **Language Base Attribute ID List**: Support for internationalized attribute retrieval.

10. **Performance Optimizations**: Caching and other optimizations for improved performance.

## Usage Examples

### Client Example

```rust
// Create an SDP client
let mut client = SdpClient::new();

// Connect to an SDP server
client.connect()?;

// Define service UUIDs to search for
let spp_uuid = Uuid::Uuid16(0x1101);  // Serial Port Profile

// Discover services
let services = client.discover_services(&[spp_uuid])?;

// Display found services
for service in services {
    println!("Service handle: 0x{:08X}", service.handle);
    
    // Get service attributes
    let attrs = client.get_service_attributes(
        service.handle,
        &[0x0001, 0x0004, 0x0100]  // ServiceClassIDList, ProtocolDescriptorList, ServiceName
    )?;
    
    // Process attributes
    // ...
}

// Disconnect
client.disconnect()?;
```

### Server Example

```rust
// Create an SDP server
let mut server = SdpServer::new();

// Create a service record for Serial Port Profile
let mut attributes = HashMap::new();
attributes.insert(0x0001, DataElement::Sequence(vec![
    DataElement::Uuid(Uuid::Uuid16(0x1101))
]));

// Protocol descriptor list
attributes.insert(0x0004, DataElement::Sequence(vec![
    // L2CAP
    DataElement::Sequence(vec![
        DataElement::Uuid(Uuid::Uuid16(0x0100)),
    ]),
    // RFCOMM
    DataElement::Sequence(vec![
        DataElement::Uuid(Uuid::Uuid16(0x0003)),
        DataElement::Uint8(1),  // RFCOMM channel
    ]),
]));

// Service name
attributes.insert(0x0100, DataElement::TextString("Serial Port".to_string()));

// Create the service record
let service = ServiceRecord {
    service_class_id_list: vec![Uuid::Uuid16(0x1101)],
    attributes,
    handle: 0,  // Will be assigned by the server
};

// Register the service
let handle = server.register_service(service);
println!("Registered service with handle: 0x{:08X}", handle);

// Server main loop would handle incoming requests
// ...
```

## Development and Testing

The SDP implementation includes basic structures and functions but lacks complete test coverage. Future work should include:

1. Unit tests for protocol message encoding/decoding
2. Tests for service record manipulation
3. Integration tests with L2CAP
4. Conformance tests against the Bluetooth SDP specification

```bash
cargo test --package rustyblue --lib -- sdp::tests
```