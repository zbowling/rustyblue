use rustyblue::gap::*;
use rustyblue::hci::*;
use rustyblue::l2cap::*;
/// Example demonstrating L2CAP Credit-Based Flow Control for BLE
use rustyblue::*;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("L2CAP LE Credit-Based Flow Control Example");
    println!("------------------------------------------");

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

    // Create L2CAP manager for BLE
    let l2cap_manager = L2capManager::new(ConnectionType::LE);
    println!("Created L2CAP manager for LE");

    // Data callback function - this is called when data is received on the channel
    let data_callback = |data: &[u8]| -> L2capResult<()> {
        println!("\nReceived data: {:?}", data);

        // Print as text if possible
        if let Ok(text) = std::str::from_utf8(data) {
            println!("Received text: {}", text);
        }

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
            ChannelEvent::ConnectionParameterUpdateRequest { identifier, params } => {
                println!("Connection parameter update request:");
                println!(
                    "  Interval: {}-{} (1.25ms units)",
                    params.conn_interval_min, params.conn_interval_max
                );
                println!("  Latency: {} events", params.conn_latency);
                println!("  Timeout: {} (10ms units)", params.supervision_timeout);
            }
            _ => {
                println!("Other channel event: {:?}", event);
            }
        }
        Ok(())
    };

    // Register the ATT protocol PSM (0x001F)
    println!("Registering ATT PSM (0x001F)...");
    let policy = ConnectionPolicy {
        min_security_level: SecurityLevel::None,
        authorization_required: false,
        auto_accept: true,
    };

    l2cap_manager.register_psm(
        PSM::ATT,
        Some(Arc::new(Mutex::new(data_callback))),
        Some(Arc::new(Mutex::new(event_callback))),
        policy,
    )?;

    println!("ATT PSM registered successfully");

    // Create a GAP adapter
    let gap_adapter = GapAdapter::new(socket.clone());

    // Scan for BLE devices
    println!("\nScanning for BLE devices...");
    let devices = match gap_adapter.scan_le(Duration::from_secs(5)) {
        Ok(devices) => {
            println!("Found {} BLE devices:", devices.len());
            for (i, device) in devices.iter().enumerate() {
                println!("{}: {} - {:?}", i + 1, device.address, device.name);
            }
            devices
        }
        Err(err) => {
            eprintln!("Failed to scan for BLE devices: {}", err);
            return Err(err.into());
        }
    };

    if devices.is_empty() {
        println!("No BLE devices found. Exiting.");
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
    println!(
        "Selected device: {} - {:?}",
        selected_device.address, selected_device.name
    );

    // Connect to the device
    println!("Connecting to BLE device...");
    let hci_handle = match gap_adapter.connect_le(&selected_device.address) {
        Ok(handle) => {
            println!("Connected to BLE device, HCI handle: 0x{:04X}", handle);
            handle
        }
        Err(err) => {
            eprintln!("Failed to connect to BLE device: {}", err);
            return Err(err.into());
        }
    };

    // Now establish an L2CAP LE credit-based connection
    println!("Establishing L2CAP LE credit-based connection to ATT PSM...");
    let channel_id = match l2cap_manager.connect(PSM::ATT, hci_handle) {
        Ok(cid) => {
            println!("L2CAP connection established, CID: 0x{:04X}", cid);
            cid
        }
        Err(err) => {
            eprintln!("Failed to establish L2CAP connection: {}", err);
            // Disconnect HCI
            let _ = gap_adapter.disconnect(hci_handle);
            return Err(err.into());
        }
    };

    // Send and receive data loop with credit management
    println!("\nConnection established. Type messages to send or 'quit' to exit.");
    println!("'credits <N>' to send N credits to the remote device.");

    loop {
        print!("> ");
        io::stdout().flush()?;

        input.clear();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input == "quit" {
            break;
        } else if input.starts_with("credits ") {
            if let Ok(credits) = input
                .split_whitespace()
                .nth(1)
                .unwrap_or("0")
                .parse::<u16>()
            {
                println!("Sending {} credits to remote device", credits);
                // In a full implementation, you would update credits with:
                // l2cap_manager.send_le_credits(channel_id, credits);
            } else {
                println!("Invalid credit value");
            }
            continue;
        }

        // Send the message
        match l2cap_manager.send_data(channel_id, input.as_bytes()) {
            Ok(_) => println!("Message sent"),
            Err(e) => {
                println!("Failed to send message: {}", e);

                // Check if we need more credits
                if let L2capError::ResourceLimitReached = e {
                    println!("Out of credits! Waiting for more credits from remote device...");
                }
            }
        }

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
    l2cap_manager.unregister_psm(PSM::ATT)?;

    println!("Example completed successfully.");
    Ok(())
}
