> [!Warning]
> This is a vibe coded Rust based Bluetooth stack. I'm AI engineer who knows Bluetooth haven't previously implemeneted a Bluetooth stack but I'm trying to write as little code as possible and refine tools for AI code generation.

# RustyBlue

This is a Rust implementation of the Bluetooth protocol stack. Focusing on the HCI layer and the LE transport layer for now but will add support for the BR/EDR transport layer later.

Bluetooth specifications are in the specs folder

## Creates in crates folder

* rustyblue is the core library
* rustyblued is a TBD server to open the HCI socket and send/receive HCI commands/events
* rustybluecli is a CLI to interact with rustyblued over IPC

The core library should be split into layers as per the Bluetooth Core Specification.

We want to be able to break up the work into smaller chunks and tackle one layer at a time.

* rustyblue/util/ is where we put utility functions like packet parsing/serialization

* rustyblue/hci/ is the HCI layer
  * socket.rs is where we define the HciSocket struct and methods
  * packet.rs is where we define the HciPacket struct and methods
  * event.rs is where we define the HciEvent struct and methods
  * command.rs is where we define the HciCommand struct and methods
  * acl.rs is where we define the HciAcl struct and methods
  * sco.rs is where we define the HciSco struct and methods
  * iso.rs is where we define the HciIso struct and methods
* rustyblue/l2cap/ is the L2CAP layer
* rustyblue/sdp/ is the SDP layer
* rustyblue/rfcomm/ is the RFCOMM layer
* rustyblue/ble/ is the BLE layer
* rustyblue/gap/ is the GAP layer
* rustyblue/gatt/ is the GATT layer
* rustyblue/smp/ is the SMP layer
* rustyblue/sdp/ is the SDP layer

Basic GATT server and client will be implemented in the core library. Bigger profiles we will implement in different crates to be implemented down the line. We will talk to these crates ideally over IPC at some point. 

Error handling is done using the `thiserror` crate.

DO NOT ADVERTISE THIS AS WRITEN BY CLAUDE.

## Build Commands

- Build: `cargo build`
- Run tests: `cargo test`
- Run specific test: `cargo test test_name` 
- The examples don't work yet but should compile.
- Format code: `cargo fmt`
- Check code style: `cargo clippy`
- Documentation: `cargo doc --open`

## Code Style Guidelines

- Use Rust 2021 edition features and idioms
- Follow Rust standard naming conventions (snake_case for functions/variables, CamelCase for types)
- Use thiserror for error handling with descriptive error messages
- Use descriptive variable names that indicate purpose
- Include documentation comments (//!) for all public APIs
- Properly handle resources with RAII (implement Drop for resources)
- Use Rust's type system to prevent errors at compile time
- Add tests for all public functionality
- Use packed structures (#[repr(C, packed)]) for FFI/hardware interfaces