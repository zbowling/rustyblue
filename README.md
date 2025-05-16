# RustyBlue: Rust Bluetooth Protocol Stack

RustyBlue is a comprehensive implementation of the Bluetooth protocol stack in Rust, focusing on both Bluetooth Classic and Bluetooth Low Energy (BLE).

## Project Structure

The project is organized into multiple crates:

### rustyblue
The core library that implements the Bluetooth protocol stack layers:
- HCI (Host Controller Interface)
- L2CAP (Logical Link Control and Adaptation Protocol)
- ATT (Attribute Protocol)
- GATT (Generic Attribute Profile)
- GAP (Generic Access Profile)
- SMP (Security Manager Protocol)
- SDP (Service Discovery Protocol)

### rustyblued
A daemon process that manages Bluetooth adapters and provides a D-Bus interface for applications.

### rustybluecli
A command-line interface for interacting with Bluetooth devices.

## Architecture

RustyBlue is structured according to the Bluetooth Core Specification v5.2:

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

Each protocol layer is implemented in a separate module, with clear interfaces between them.

## Features

- Bluetooth HCI communication
- L2CAP channel management and multiplexing
- ATT client and server implementation
- GATT client and server implementation
- GAP device discovery and connection management
- SMP for secure pairing and encryption
- SDP for service discovery (Bluetooth Classic)

## Requirements

- Linux operating system
- Bluetooth adapter
- Root privileges (for opening raw HCI sockets)

## Development

### Building the Project

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Running the CLI

```bash
cargo run --bin rustybluecli -- scan
```

## References

- [Bluetooth Core Specification v5.2](https://www.bluetooth.com/specifications/bluetooth-core-specification/)
- [Bluetooth SIG Assigned Numbers](https://www.bluetooth.com/specifications/assigned-numbers/)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
