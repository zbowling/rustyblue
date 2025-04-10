# RustyBlue

A Rust library for Bluetooth HCI (Host Controller Interface) communication on Linux systems.

## Features

- Open raw HCI sockets for low-level Bluetooth communication
- Simple and safe API for working with Bluetooth HCI

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

### Running the Example

To run the example, you'll need root privileges:

```bash
sudo cargo run --example open_hci_socket
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 