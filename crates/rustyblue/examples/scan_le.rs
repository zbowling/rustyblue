//! Example: Scanning for BLE devices
//! 
//! This example demonstrates how to scan for BLE devices using the rustyblue library.
//! 
//! Note: This example requires root privileges to run, as opening raw HCI sockets
//! requires elevated permissions.

use std::time::Duration;
use rustyblue::{HciSocket, hci::packet::HciCommand, hci::packet::LeAdvertisingReport, scan::parse_advertising_data};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Opening HCI socket for device 0...");
    let socket = HciSocket::open(0)?;
    
    println!("Setting up LE scan parameters...");
    socket.send_command(&HciCommand::LeSetScanParameters {
        scan_type: 1,          // 0 = passive, 1 = active
        scan_interval: 0x0010, // 10ms in 0.625ms units (0x0010 * 0.625 = 10ms)
        scan_window: 0x0010,   // 10ms in 0.625ms units
        own_address_type: 0,   // Public Device Address
        filter_policy: 0,      // Accept all advertisements
    })?;
    
    println!("Enabling LE scanning...");
    socket.send_command(&HciCommand::LeSetScanEnable {
        enable: true,
        filter_duplicates: true,
    })?;
    
    println!("Scanning for 10 seconds...");
    
    // Note: A proper implementation would include reading events from the socket
    // and processing them. For now, we're just demonstrating how to set up scanning.
    std::thread::sleep(Duration::from_secs(10));
    
    println!("Disabling LE scanning...");
    socket.send_command(&HciCommand::LeSetScanEnable {
        enable: false,
        filter_duplicates: false,
    })?;
    
    println!("Scan complete!");
    
    Ok(())
}