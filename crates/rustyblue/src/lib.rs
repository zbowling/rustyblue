//! RustyBlue - A Rust library for Bluetooth HCI communication
//!
//! This library provides functionality to interact with Bluetooth HCI (Host Controller Interface)
//! on Unix systems, focusing primarily on Bluetooth Low Energy (BLE) functionality.
//! It includes GATT client and server implementations for interacting with Bluetooth LE devices
//! as well as ATT, SMP, and L2CAP layers.

pub mod att;
pub mod error;
pub mod gap;
pub mod gatt;
pub mod hci;
pub mod l2cap;
pub mod scan;
pub mod sdp;
pub mod smp;
pub mod uuid;

// Re-export common types for convenience
pub use att::{AttClient, AttError, AttServer, Attribute, AttributeDatabase};
pub use error::HciError;
pub use gap::{AddressType, BdAddr, Device, GapAdapter};
pub use gatt::{
    Characteristic, CharacteristicProperty, GattClient, GattServer, GattServerConfig, Service, Uuid,
};
pub use hci::{HciCommand, HciEvent, HciSocket, LeAdvertisingReport};
pub use l2cap::{L2capChannel, L2capChannelType, L2capError, L2capManager};
pub use scan::{parse_advertising_data, scan_le};
pub use sdp::{SdpClient, SdpServer, ServiceRecord};
pub use smp::{AuthRequirements, IoCapability, KeyDistribution, SecurityLevel, SmpManager};
// pub use uuid::Uuid; // Removed re-export to fix privacy issues

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
