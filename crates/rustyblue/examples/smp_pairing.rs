/// Example demonstrating SMP pairing between devices
use rustyblue::*;
use rustyblue::smp::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("SMP Pairing Example");
    println!("-----------------");
    
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
    
    // Create an L2CAP manager
    let l2cap_manager = Arc::new(L2capManager::new(ConnectionType::Le));
    
    // Create a key store
    let key_store = Box::new(MemoryKeyStore::new()) as Box<dyn KeyStore + Send + Sync>;
    
    // Create SMP manager
    let smp_manager = SmpManager::new(l2cap_manager.clone(), Arc::new(socket.clone()), key_store);
    println!("Created SMP manager");
    
    // Configure SMP features
    println!("Configuring SMP features...");
    let mut smp_manager = smp_manager;
    smp_manager.set_io_capability(IoCapability::DisplayYesNo);
    smp_manager.set_auth_requirements(AuthRequirements::secure());
    
    // Set up event callback
    smp_manager.set_event_callback(|event| -> SmpResult<()> {
        match event {
            SmpEvent::PairingRequest(addr, features) => {
                println!("Pairing request from {}: IO Capability={:?}, Auth={:?}",
                         addr, features.io_capability, features.auth_req.secure_connections);
            },
            SmpEvent::PairingResponse(addr, features) => {
                println!("Pairing response from {}: IO Capability={:?}, Auth={:?}",
                         addr, features.io_capability, features.auth_req.secure_connections);
            },
            SmpEvent::DisplayPasskey(addr, passkey) => {
                println!("Display passkey {} to user for device {}", passkey, addr);
            },
            SmpEvent::PasskeyRequest(addr) => {
                println!("Passkey request from device {}", addr);
                // In a real application, we would prompt the user
                // For this example, we just return a fixed value
            },
            SmpEvent::NumericComparisonRequest(addr, value) => {
                println!("Numeric comparison request: Does {} match on device {}?", value, addr);
                // In a real application, we would prompt the user
                // For this example, we just accept
            },
            SmpEvent::PairingComplete(addr, success) => {
                println!("Pairing with {} {}", addr, 
                         if success { "succeeded" } else { "failed" });
            },
            SmpEvent::KeysReceived(addr) => {
                println!("Keys received from {}", addr);
            },
            SmpEvent::SecurityLevelChanged(addr, level) => {
                println!("Security level for {} changed to {:?}", addr, level);
            },
            SmpEvent::PairingFailed(addr, error) => {
                println!("Pairing with {} failed: {}", addr, error);
            },
            _ => {
                println!("Other SMP event: {:?}", event);
            }
        }
        Ok(())
    });
    
    // Set up passkey callback
    smp_manager.set_passkey_callback(|addr| -> SmpResult<u32> {
        println!("Enter passkey for device {}:", addr);
        print!("> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        let passkey = input.trim().parse::<u32>().unwrap_or(0);
        
        Ok(passkey)
    });
    
    // Set up comparison callback
    smp_manager.set_comparison_callback(|addr, value| -> SmpResult<bool> {
        println!("Does the value {} match on device {}? (y/n)", value, addr);
        print!("> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        let confirmation = input.trim().to_lowercase();
        
        Ok(confirmation == "y" || confirmation == "yes")
    });
    
    // Create a GAP adapter for device discovery
    let gap_adapter = GapAdapter::new(socket.clone());
    
    // Scan for devices
    println!("\nScanning for BLE devices...");
    let devices = match gap_adapter.scan_le(Duration::from_secs(5)) {
        Ok(devices) => {
            println!("Found {} BLE devices:", devices.len());
            for (i, device) in devices.iter().enumerate() {
                println!("{}: {} - {:?}", i + 1, device.address, device.name);
            }
            devices
        },
        Err(err) => {
            eprintln!("Failed to scan for devices: {}", err);
            return Err(err.into());
        }
    };
    
    if devices.is_empty() {
        println!("No devices found. Exiting.");
        return Ok(());
    }
    
    // Ask the user to select a device
    print!("Select a device to pair with (1-{}): ", devices.len());
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
    let hci_handle = match gap_adapter.connect_le(&selected_device.address) {
        Ok(handle) => {
            println!("Connected to device, HCI handle: 0x{:04X}", handle);
            handle
        },
        Err(err) => {
            eprintln!("Failed to connect to device: {}", err);
            return Err(err.into());
        }
    };
    
    // Check if already paired
    let is_paired = match smp_manager.is_paired(&selected_device.address) {
        Ok(paired) => paired,
        Err(err) => {
            println!("Error checking pairing status: {}", err);
            false
        }
    };
    
    if is_paired {
        println!("Device is already paired.");
        
        // Get security level
        match smp_manager.security_level(&selected_device.address) {
            Ok(level) => println!("Current security level: {:?}", level),
            Err(err) => println!("Error getting security level: {}", err),
        }
        
        // Ask if user wants to unpair
        print!("Do you want to unpair? (y/n): ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        if input.trim().to_lowercase() == "y" {
            match smp_manager.remove_pairing(&selected_device.address) {
                Ok(_) => println!("Device unpaired successfully."),
                Err(err) => println!("Error unpairing device: {}", err),
            }
        }
    } else {
        // Initiate pairing
        println!("Initiating pairing...");
        match smp_manager.initiate_pairing(selected_device.address) {
            Ok(_) => println!("Pairing process started."),
            Err(err) => println!("Error starting pairing: {}", err),
        }
        
        // Wait for pairing to complete
        println!("Waiting for pairing to complete...");
        println!("(Note: This example doesn't handle the complete pairing process yet)");
        println!("Press Enter to continue...");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
    }
    
    // Disconnect from the device
    println!("Disconnecting...");
    match gap_adapter.disconnect(hci_handle) {
        Ok(_) => println!("Disconnected successfully."),
        Err(err) => println!("Error disconnecting: {}", err),
    }
    
    // List all paired devices
    println!("\nPaired devices:");
    match smp_manager.paired_devices() {
        Ok(devices) => {
            if devices.is_empty() {
                println!("No paired devices.");
            } else {
                for (i, device) in devices.iter().enumerate() {
                    println!("{}: {}", i + 1, device);
                }
            }
        },
        Err(err) => println!("Error listing paired devices: {}", err),
    }
    
    println!("Example completed.");
    Ok(())
}