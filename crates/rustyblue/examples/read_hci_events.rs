//! Example: Reading HCI events
//! 
//! This example demonstrates how to read HCI events using the rustyblue library.

use rustyblue::hci::{HciSocket, HciCommand};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Opening HCI socket for device 0...");
    let socket = HciSocket::open(0)?;
    
    // Set event mask to receive all events
    let event_mask = 0xFFFFFFFFFFFFFFFF; // All events
    socket.send_command(&HciCommand::SetEventMask { event_mask })?;
    println!("Set event mask");
    
    // Send a Reset command to get some events
    println!("Sending HCI Reset command...");
    socket.send_command(&HciCommand::Reset)?;
    println!("Reset command sent successfully!");
    
    // Read events for a few seconds
    println!("\nReading HCI events for 5 seconds...");
    let start_time = std::time::Instant::now();
    
    while start_time.elapsed() < Duration::from_secs(5) {
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
    
    println!("Finished reading events");
    Ok(())
} 