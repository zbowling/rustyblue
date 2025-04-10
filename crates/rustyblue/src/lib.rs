//! RustyBlue - A Rust library for Bluetooth HCI communication
//! 
//! This library provides functionality to interact with Bluetooth HCI (Host Controller Interface)
//! on Unix systems, focusing primarily on Bluetooth Low Energy (BLE) functionality.
//! It also includes a GATT client implementation for interacting with GATT servers.

pub mod error;
pub mod hci;
pub mod scan;
pub mod gatt;

// Re-export common types for convenience
pub use error::HciError;
pub use hci::{HciSocket, HciCommand, HciEvent, LeAdvertisingReport};
pub use scan::{scan_le, parse_advertising_data};
pub use gatt::{GattClient, Service, Characteristic, CharacteristicProperty, Uuid};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_hci_socket() {
        // This test will only pass if run with sufficient privileges
        // and if a Bluetooth adapter is available
        let result = HciSocket::open(0);
        
        // We don't assert here because the test might fail in environments
        // without Bluetooth hardware or sufficient privileges
        if let Ok(socket) = result {
            assert!(socket.as_raw_fd() > 0);
        }
    }
}