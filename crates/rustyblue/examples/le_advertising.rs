use rustyblue::hci::{HciSocket, HciCommand};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open HCI socket for device 0
    let socket = match HciSocket::open(0) {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("Failed to open HCI socket: {}", e);
            eprintln!("This might be because:");
            eprintln!("1. No Bluetooth adapter is available");
            eprintln!("2. The Bluetooth adapter is not powered on");
            eprintln!("3. You don't have sufficient permissions to access the Bluetooth device");
            return Err(e.into());
        }
    };
    
    // Set LE event mask to receive advertising events
    let event_mask = 0x1F; // Enable all LE events
    socket.send_command(&HciCommand::LeSetEventMask { event_mask })?;
    println!("Set LE event mask");
    
    // Set random address for advertising
    let random_addr = [0x02, 0x00, 0x00, 0xE0, 0x00, 0x00];
    socket.send_command(&HciCommand::LeSetRandomAddress { address: random_addr })?;
    println!("Set random address");
    
    // Configure advertising parameters
    socket.send_command(&HciCommand::LeSetAdvertisingParameters {
        min_interval: 0x0020, // 32 * 0.625ms = 20ms
        max_interval: 0x0020, // 32 * 0.625ms = 20ms
        advertising_type: 0x00, // Connectable undirected advertising
        own_address_type: 0x01, // Random device address
        peer_address_type: 0x00, // Public device address
        peer_address: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Not used
        channel_map: 0x07, // All channels
        filter_policy: 0x00, // Allow all connections
    })?;
    println!("Set advertising parameters");
    
    // Set advertising data
    let adv_data = vec![
        0x02, // Length
        0x01, // Type (Flags)
        0x06, // Value (LE General Discoverable Mode, BR/EDR Not Supported)
    ];
    socket.send_command(&HciCommand::LeSetAdvertisingData { data: adv_data })?;
    println!("Set advertising data");
    
    // Enable advertising
    socket.send_command(&HciCommand::LeSetAdvertisingEnable { enable: true })?;
    println!("Started advertising");
    
    // Wait for user input to stop advertising
    println!("Press Enter to stop advertising...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    // Disable advertising
    socket.send_command(&HciCommand::LeSetAdvertisingEnable { enable: false })?;
    println!("Stopped advertising");
    
    Ok(())
} 