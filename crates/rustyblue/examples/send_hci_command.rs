//! Example: Sending HCI commands
//! 
//! This example demonstrates how to send various HCI commands using the rustyblue library.

use rustyblue::hci::{HciSocket, HciCommand};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Opening HCI socket for device 0...");
    let socket = HciSocket::open(0)?;
    
    // Send a Reset command
    println!("Sending HCI Reset command...");
    socket.send_command(&HciCommand::Reset)?;
    println!("Reset command sent successfully!");
    
    // Enable LE scanning
    println!("\nEnabling LE scanning...");
    socket.send_command(&HciCommand::LeSetScanParameters {
        scan_type: 1,          // Active scanning
        scan_interval: 0x0010, // 10ms in 0.625ms units
        scan_window: 0x0010,   // 10ms in 0.625ms units
        own_address_type: 0,   // Public Device Address
        filter_policy: 0,      // Accept all advertisements
    })?;
    println!("LE scan parameters set!");
    
    socket.send_command(&HciCommand::LeSetScanEnable {
        enable: true,
        filter_duplicates: true,
    })?;
    println!("LE scan enabled!");
    
    // Wait a bit then disable scanning
    std::thread::sleep(std::time::Duration::from_secs(5));
    
    println!("\nDisabling LE scanning...");
    socket.send_command(&HciCommand::LeSetScanEnable {
        enable: false,
        filter_duplicates: false,
    })?;
    println!("LE scan disabled!");
    
    Ok(())
} 