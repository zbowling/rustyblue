//! Example: LE Scanning
//! 
//! This example demonstrates how to scan for LE devices using the rustyblue library.

use rustyblue::hci::{HciSocket, HciCommand};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Opening HCI socket for device 0...");
    let socket = HciSocket::open(0)?;
    
    // Set LE event mask to receive advertising events
    let event_mask = 0x1F; // Enable all LE events
    socket.send_command(&HciCommand::LeSetEventMask { event_mask })?;
    println!("Set LE event mask");
    
    // Configure scan parameters
    socket.send_command(&HciCommand::LeSetScanParameters {
        scan_type: 1,          // Active scanning
        scan_interval: 0x0010, // 10ms in 0.625ms units
        scan_window: 0x0010,   // 10ms in 0.625ms units
        own_address_type: 0,   // Public Device Address
        filter_policy: 0,      // Accept all advertisements
    })?;
    println!("Set scan parameters");
    
    // Enable scanning
    socket.send_command(&HciCommand::LeSetScanEnable {
        enable: true,
        filter_duplicates: true,
    })?;
    println!("Started scanning for LE devices...");
    
    // Read events for a few seconds
    println!("\nScanning for 10 seconds...");
    let start_time = std::time::Instant::now();
    
    while start_time.elapsed() < Duration::from_secs(10) {
        match socket.read_event_timeout(Some(Duration::from_millis(100))) {
            Ok(event) => {
                println!("Received event: {:?}", event);
            },
            Err(e) => {
                if e.to_string().contains("Timed out") {
                    // This is expected when no events are available
                    continue;
                }
                eprintln!("Error reading event: {}", e);
            }
        }
    }
    
    // Disable scanning
    socket.send_command(&HciCommand::LeSetScanEnable {
        enable: false,
        filter_duplicates: false,
    })?;
    println!("Stopped scanning");
    
    Ok(())
} 