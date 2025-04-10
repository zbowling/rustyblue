//! Example: Opening an HCI socket
//! 
//! This example demonstrates how to open an HCI socket using the rustyblue library.

use rustyblue::hci::HciSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Opening HCI socket for device 0...");
    
    match HciSocket::open(0) {
        Ok(socket) => {
            println!("Successfully opened HCI socket!");
            println!("Socket file descriptor: {}", socket.as_raw_fd());
            
            // The socket will be automatically closed when it goes out of scope
            println!("Socket will be closed when this function returns.");
        },
        Err(e) => {
            eprintln!("Failed to open HCI socket: {}", e);
            eprintln!("This might be because:");
            eprintln!("1. You don't have sufficient permissions to access the Bluetooth device");
            eprintln!("2. No Bluetooth adapter is available");
            eprintln!("3. The Bluetooth adapter is not powered on");
        }
    }
    
    Ok(())
} 