//! RustyBlue - A Rust library for Bluetooth HCI communication
//! 
//! This library provides functionality to interact with Bluetooth HCI (Host Controller Interface)
//! on Unix systems, focusing primarily on Bluetooth Low Energy (BLE) functionality.
//! It includes GATT client and server implementations for interacting with Bluetooth LE devices
//! as well as ATT, SMP, and L2CAP layers.

pub mod error;
pub mod hci;
pub mod scan;
pub mod gatt;
pub mod sdp;
pub mod gap;
pub mod l2cap;
pub mod smp;
pub mod att;

// Re-export common types for convenience
pub use error::HciError;
pub use hci::{HciSocket, HciCommand, HciEvent, LeAdvertisingReport};
pub use scan::{scan_le, parse_advertising_data};
pub use gatt::{GattClient, GattServer, GattServerConfig, Service, Characteristic, CharacteristicProperty, Uuid};
pub use sdp::{SdpClient, SdpServer, ServiceRecord};
pub use gap::{GapAdapter, BdAddr, AddressType, Device};
pub use l2cap::{L2capManager, L2capChannel, L2capChannelType, L2capError};
pub use smp::{SmpManager, IoCapability, SecurityLevel, AuthRequirements, KeyDistribution};
pub use att::{AttClient, AttServer, AttributeDatabase, Attribute, AttError};

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