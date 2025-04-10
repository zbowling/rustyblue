/// Example demonstrating an L2CAP server that accepts connections
use rustyblue::*;
use rustyblue::l2cap::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::io::{self, Write};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("L2CAP Server Example");
    println!("--------------------");
    
    // Open HCI socket
    let socket = match HciSocket::open(0) {
        Ok(socket) => {
            println!("Successfully opened HCI socket");
            socket
        },
        Err(err) => {
            eprintln!("Failed to open HCI socket: {}", err);
            eprintln!("Note: This example requires root/sudo privileges");
            return Err(err.into());
        }
    };
    
    // Create L2CAP manager for Classic Bluetooth
    let l2cap_manager = L2capManager::new(ConnectionType::Classic);
    println!("Created L2CAP manager");
    
    // Keep track of connected channels
    let connected_channels = Arc::new(Mutex::new(HashMap::new()));
    let connected_channels_clone = connected_channels.clone();
    
    // Data callback function - called when data is received on the channel
    let data_callback = move |data: &[u8]| -> L2capResult<()> {
        println!("Received data: {:?}", data);
        
        // Echo the data back if it's text
        if let Ok(text) = std::str::from_utf8(data) {
            println!("Received text: {}", text);
        }
        
        Ok(())
    };
    
    // Event callback function - called for channel state changes
    let event_callback = move |event: ChannelEvent| -> L2capResult<()> {
        match event {
            ChannelEvent::Connected { cid, psm } => {
                println!("Channel connected: CID={}, PSM={:?}", cid, psm);
                
                // Store the channel ID
                let mut channels = connected_channels_clone.lock().unwrap();
                channels.insert(cid, psm);
            },
            ChannelEvent::Disconnected { cid, psm, reason } => {
                println!("Channel disconnected: CID={}, PSM={:?}, Reason={}", cid, psm, reason);
                
                // Remove the channel ID
                let mut channels = connected_channels_clone.lock().unwrap();
                channels.remove(&cid);
            },
            ChannelEvent::ConnectionRequest { identifier, psm, source_cid } => {
                println!("Connection request: ID={}, PSM={:?}, Source CID={}", 
                         identifier, psm, source_cid);
                
                // The auto_accept policy will handle accepting the connection
            },
            _ => {
                println!("Other channel event: {:?}", event);
            }
        }
        Ok(())
    };
    
    // Register an RFCOMM PSM (most commonly used for profiles)
    println!("Registering RFCOMM PSM (0x0003)...");
    let policy = ConnectionPolicy {
        min_security_level: SecurityLevel::None,
        authorization_required: false,
        auto_accept: true, // Automatically accept incoming connections
    };
    
    l2cap_manager.register_psm(
        PSM::RFCOMM, 
        Some(Arc::new(Mutex::new(data_callback))),
        Some(Arc::new(Mutex::new(event_callback))),
        policy
    )?;
    
    println!("RFCOMM PSM registered successfully");
    
    // Also register a dynamic PSM for a custom service
    let custom_psm = obtain_dynamic_psm();
    println!("Registering custom PSM: {:?} (0x{:04X})...", custom_psm, custom_psm.value());
    
    l2cap_manager.register_psm(
        custom_psm,
        Some(Arc::new(Mutex::new(data_callback.clone()))),
        Some(Arc::new(Mutex::new(event_callback.clone()))),
        policy
    )?;
    
    println!("Custom PSM registered successfully");
    
    // Make the Bluetooth adapter discoverable to allow incoming connections
    println!("\nNOTE: In a real application, you would now:");
    println!("1. Make the Bluetooth adapter discoverable");
    println!("2. Start an SDP service to advertise the L2CAP service");
    println!("3. Wait for incoming connections");
    
    // Start a simple loop to allow sending messages on connected channels
    println!("\nServer running. Press Ctrl+C to exit.");
    println!("Type a message to send to all connected channels or 'quit' to exit.");
    
    let mut input = String::new();
    loop {
        print!("> ");
        io::stdout().flush()?;
        
        input.clear();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if input == "quit" {
            break;
        }
        
        // Send the message to all connected channels
        let channels = connected_channels.lock().unwrap();
        if channels.is_empty() {
            println!("No connected channels");
        } else {
            for (cid, _) in channels.iter() {
                match l2cap_manager.send_data(*cid, input.as_bytes()) {
                    Ok(_) => println!("Sent message to channel {}", cid),
                    Err(e) => println!("Failed to send message to channel {}: {}", cid, e),
                }
            }
        }
    }
    
    // Clean up
    println!("Unregistering PSMs...");
    l2cap_manager.unregister_psm(PSM::RFCOMM)?;
    l2cap_manager.unregister_psm(custom_psm)?;
    
    println!("Example completed successfully.");
    Ok(())
}