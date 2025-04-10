/// Example demonstrating an L2CAP client that connects to a server
use rustyblue::*;
use rustyblue::l2cap::*;
use rustyblue::gap::*;
use rustyblue::hci::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("L2CAP Client Example");
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
    
    // Create a GAP adapter for device discovery
    let gap_adapter = GapAdapter::new(socket.clone());
    
    // Create L2CAP manager for Classic Bluetooth
    let l2cap_manager = L2capManager::new(ConnectionType::Classic);
    println!("Created L2CAP manager");
    
    // Data callback function - called when data is received on the channel
    let data_callback = |data: &[u8]| -> L2capResult<()> {
        println!("\nReceived data: {:?}", data);
        
        // Print as text if possible
        if let Ok(text) = std::str::from_utf8(data) {
            println!("Received text: {}", text);
        }
        
        Ok(())
    };
    
    // Event callback function - called for channel state changes
    let event_callback = |event: ChannelEvent| -> L2capResult<()> {
        match event {
            ChannelEvent::Connected { cid, psm } => {
                println!("Channel connected: CID={}, PSM={:?}", cid, psm);
            },
            ChannelEvent::Disconnected { cid, psm, reason } => {
                println!("Channel disconnected: CID={}, PSM={:?}, Reason={}", cid, psm, reason);
            },
            ChannelEvent::ConfigChanged { cid, config } => {
                println!("Channel configuration changed: CID={}", cid);
                // Display MTU if present
                if let Some(mtu) = config.mtu {
                    println!("  MTU: {}", mtu);
                }
            },
            _ => {
                println!("Other channel event: {:?}", event);
            }
        }
        Ok(())
    };
    
    // Register for RFCOMM PSM (we will connect to this on the server)
    println!("Registering RFCOMM PSM (0x0003)...");
    let policy = ConnectionPolicy {
        min_security_level: SecurityLevel::None,
        authorization_required: false,
        auto_accept: true,
    };
    
    l2cap_manager.register_psm(
        PSM::RFCOMM, 
        Some(Arc::new(Mutex::new(data_callback))),
        Some(Arc::new(Mutex::new(event_callback))),
        policy
    )?;
    
    println!("RFCOMM PSM registered successfully");
    
    // Discover nearby devices
    println!("\nScanning for devices...");
    let devices = match gap_adapter.discover_devices(Duration::from_secs(5)) {
        Ok(devices) => {
            println!("Found {} devices:", devices.len());
            for (i, device) in devices.iter().enumerate() {
                println!("{}: {} - {:?}", i + 1, device.address, device.name);
            }
            devices
        },
        Err(err) => {
            eprintln!("Failed to discover devices: {}", err);
            return Err(err.into());
        }
    };
    
    if devices.is_empty() {
        println!("No devices found. Exiting.");
        return Ok(());
    }
    
    // Ask the user to select a device
    print!("Select a device (1-{}): ", devices.len());
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let selection = input.trim().parse::<usize>().unwrap_or(0);
    
    if selection < 1 || selection > devices.len() {
        println!("Invalid selection. Exiting.");
        return Ok(());
    }
    
    let selected_device = &devices[selection - 1];
    println!("Selected device: {} - {:?}", selected_device.address, selected_device.name);
    
    // Connect to the device
    println!("Connecting to device...");
    let hci_handle = match gap_adapter.connect(&selected_device.address) {
        Ok(handle) => {
            println!("Connected to device, HCI handle: 0x{:04X}", handle);
            handle
        },
        Err(err) => {
            eprintln!("Failed to connect to device: {}", err);
            return Err(err.into());
        }
    };
    
    // Now establish an L2CAP connection
    println!("Establishing L2CAP connection to RFCOMM PSM...");
    let channel_id = match l2cap_manager.connect(PSM::RFCOMM, hci_handle) {
        Ok(cid) => {
            println!("L2CAP connection established, CID: 0x{:04X}", cid);
            cid
        },
        Err(err) => {
            eprintln!("Failed to establish L2CAP connection: {}", err);
            // Disconnect HCI
            let _ = gap_adapter.disconnect(hci_handle);
            return Err(err.into());
        }
    };
    
    // Send and receive data loop
    println!("\nConnection established. Type messages to send or 'quit' to exit.");
    
    loop {
        print!("> ");
        io::stdout().flush()?;
        
        input.clear();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if input == "quit" {
            break;
        }
        
        // Send the message
        match l2cap_manager.send_data(channel_id, input.as_bytes()) {
            Ok(_) => println!("Message sent"),
            Err(e) => println!("Failed to send message: {}", e),
        }
        
        // In a real application, we would process incoming data here
        // But the data_callback above will handle that asynchronously
        
        // Short delay to allow for response processing
        thread::sleep(Duration::from_millis(100));
    }
    
    // Disconnect L2CAP channel
    println!("Disconnecting L2CAP channel...");
    match l2cap_manager.disconnect(channel_id) {
        Ok(_) => println!("L2CAP channel disconnected"),
        Err(e) => println!("Failed to disconnect L2CAP channel: {}", e),
    }
    
    // Disconnect HCI connection
    println!("Disconnecting HCI connection...");
    match gap_adapter.disconnect(hci_handle) {
        Ok(_) => println!("HCI connection disconnected"),
        Err(e) => println!("Failed to disconnect HCI connection: {}", e),
    }
    
    // Clean up
    println!("Unregistering PSM...");
    l2cap_manager.unregister_psm(PSM::RFCOMM)?;
    
    println!("Example completed successfully.");
    Ok(())
}