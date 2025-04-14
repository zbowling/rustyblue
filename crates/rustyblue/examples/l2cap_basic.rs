use rustyblue::l2cap::*;
/// Example demonstrating basic L2CAP channel management
use rustyblue::*;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("L2CAP Basic Example");
    println!("-------------------");

    // Open HCI socket
    let socket = match HciSocket::open(0) {
        Ok(socket) => {
            println!("Successfully opened HCI socket");
            socket
        }
        Err(err) => {
            eprintln!("Failed to open HCI socket: {}", err);
            eprintln!("Note: This example requires root/sudo privileges");
            return Err(err.into());
        }
    };

    // Create L2CAP manager for Classic Bluetooth
    let l2cap_manager = L2capManager::new(ConnectionType::Classic);
    println!("Created L2CAP manager");

    // Data callback function - this is called when data is received on the channel
    let data_callback = |data: &[u8]| -> L2capResult<()> {
        println!("Received data: {:?}", data);
        Ok(())
    };

    // Event callback function - this is called for channel state changes
    let event_callback = |event: ChannelEvent| -> L2capResult<()> {
        match event {
            ChannelEvent::Connected { cid, psm } => {
                println!("Channel connected: CID={}, PSM={:?}", cid, psm);
            }
            ChannelEvent::Disconnected { cid, psm, reason } => {
                println!(
                    "Channel disconnected: CID={}, PSM={:?}, Reason={}",
                    cid, psm, reason
                );
            }
            ChannelEvent::ConfigChanged { cid, config } => {
                println!("Channel configuration changed: CID={}", cid);
                // Display MTU if present
                if let Some(mtu) = config.mtu {
                    println!("  MTU: {}", mtu);
                }
            }
            ChannelEvent::ConnectionRequest {
                identifier,
                psm,
                source_cid,
            } => {
                println!(
                    "Connection request: ID={}, PSM={:?}, Source CID={}",
                    identifier, psm, source_cid
                );
            }
            _ => {
                println!("Other channel event: {:?}", event);
            }
        }
        Ok(())
    };

    // Register a PSM (Protocol/Service Multiplexer) for SDP
    println!("Registering SDP PSM (0x0001)...");
    let policy = ConnectionPolicy {
        min_security_level: SecurityLevel::None,
        authorization_required: false,
        auto_accept: true,
    };

    l2cap_manager.register_psm(
        PSM::SDP,
        Some(Arc::new(Mutex::new(data_callback))),
        Some(Arc::new(Mutex::new(event_callback))),
        policy,
    )?;

    println!("SDP PSM registered successfully");

    // Note: In a real application, you would now:
    // 1. Create an HCI connection to a remote device (get an HCI handle)
    // 2. Connect to the remote device's SDP service
    println!("\nThis example demonstrates L2CAP setup only.");
    println!("To establish an actual connection, an HCI connection must first be established.");
    println!("See examples/gap_discovery.rs for how to discover and connect to devices.");

    // Demonstration of dynamic PSM allocation
    let dynamic_psm = obtain_dynamic_psm();
    println!(
        "\nAllocated dynamic PSM: {:?} (0x{:04X})",
        dynamic_psm,
        dynamic_psm.value()
    );

    // Sleep for a moment to keep the program running
    println!("\nWaiting for 3 seconds...");
    thread::sleep(Duration::from_secs(3));

    // Clean up
    println!("Unregistering SDP PSM...");
    l2cap_manager.unregister_psm(PSM::SDP)?;

    println!("Example completed successfully.");
    Ok(())
}
