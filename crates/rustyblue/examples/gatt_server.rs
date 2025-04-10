//! Example demonstrating a simple GATT server
//!
//! This example creates a GATT server with a custom service and characteristic
//! that can be discovered and accessed by GATT clients.

use std::sync::Arc;
use std::time::Duration;
use rustyblue::att::{AttributeDatabase, AttPermissions, AttServer, SecurityLevel};
use rustyblue::gatt::{GattServer, GattServerConfig, Uuid, CharacteristicProperty};
use rustyblue::hci::{HciSocket, HciCommand};
use rustyblue::l2cap::L2capManager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open HCI socket
    let socket = HciSocket::open(0)?;
    println!("Opened HCI socket");
    
    // Reset and initialize HCI
    socket.send_command(&HciCommand::Reset)?;
    socket.read_event()?; // Read the command complete event
    println!("Reset HCI controller");
    
    // Create L2CAP manager
    let l2cap_manager = Arc::new(L2capManager::new(socket.clone()));
    
    // Create ATT database and server
    let database = Arc::new(AttributeDatabase::new());
    let att_server = Arc::new(AttServer::new(l2cap_manager.clone(), database.clone()));
    
    // Create GATT server
    let gatt_server = GattServer::new(att_server.clone(), database.clone());
    
    // Configure GATT server
    gatt_server.set_config(GattServerConfig {
        max_mtu: 517,
        security_level: SecurityLevel::None,
    });
    
    // Start the GATT server
    gatt_server.start()?;
    println!("Started GATT server");
    
    // Create a custom service
    let service_uuid = Uuid::from_u16(0x1800); // Generic Access service UUID
    let service_handle = gatt_server.add_service(service_uuid.clone(), true)?;
    println!("Added Generic Access service: {}", service_uuid);
    
    // Device Name characteristic
    let device_name_uuid = Uuid::from_u16(0x2A00); // Device Name characteristic UUID
    let device_name_properties = CharacteristicProperty(
        CharacteristicProperty::READ
    );
    let device_name_perms = AttPermissions::read_only();
    let device_name_handle = gatt_server.add_characteristic(
        service_handle,
        device_name_uuid.clone(),
        device_name_properties,
        device_name_perms,
        b"RustyBlue Server".to_vec(),
    )?;
    println!("Added Device Name characteristic: {}", device_name_uuid);
    
    // Appearance characteristic
    let appearance_uuid = Uuid::from_u16(0x2A01); // Appearance characteristic UUID
    let appearance_properties = CharacteristicProperty(
        CharacteristicProperty::READ
    );
    let appearance_perms = AttPermissions::read_only();
    let appearance_handle = gatt_server.add_characteristic(
        service_handle,
        appearance_uuid.clone(),
        appearance_properties,
        appearance_perms,
        // Generic Computer (0x0080)
        vec![0x80, 0x00],
    )?;
    println!("Added Appearance characteristic: {}", appearance_uuid);
    
    // Create a custom service
    let custom_service_uuid = Uuid::from_u16(0x1234); // Custom service UUID
    let custom_service_handle = gatt_server.add_service(custom_service_uuid.clone(), true)?;
    println!("Added custom service: {}", custom_service_uuid);
    
    // Add a characteristic to the custom service
    let custom_char_uuid = Uuid::from_u16(0x5678); // Custom characteristic UUID
    let custom_char_properties = CharacteristicProperty(
        CharacteristicProperty::READ | 
        CharacteristicProperty::WRITE |
        CharacteristicProperty::NOTIFY
    );
    let custom_char_perms = AttPermissions::read_write();
    let custom_char_handle = gatt_server.add_characteristic(
        custom_service_handle,
        custom_char_uuid.clone(),
        custom_char_properties,
        custom_char_perms,
        b"Hello, world!".to_vec(),
    )?;
    println!("Added custom characteristic: {}", custom_char_uuid);
    
    // Add CCCD to the custom characteristic
    let cccd_handle = gatt_server.add_cccd(custom_char_handle)?;
    println!("Added CCCD to custom characteristic");
    
    // Set the controller to be discoverable and connectable
    socket.send_command(&HciCommand::WriteScanEnable {
        scan_enable: 0x03, // Inquiry and page scan enabled
    })?;
    socket.read_event()?;
    println!("Set controller to be discoverable and connectable");
    
    // Set the device name
    socket.send_command(&HciCommand::WriteLocalName {
        name: "RustyBlue Server".to_string(),
    })?;
    socket.read_event()?;
    println!("Set device name to 'RustyBlue Server'");
    
    // Enable LE advertising
    // Reset advertising parameters
    socket.send_command(&HciCommand::LeSetAdvertisingParameters {
        min_interval: 0x0800, // 1.28s
        max_interval: 0x0800, // 1.28s
        adv_type: 0x00,       // Connectable, undirected
        own_addr_type: 0x00,  // Public
        peer_addr_type: 0x00, // Public
        peer_addr: [0; 6],    // Not used
        channel_map: 0x07,    // All channels
        filter_policy: 0x00,  // No filtering
    })?;
    socket.read_event()?;
    
    // Set advertising data
    let mut adv_data = Vec::new();
    
    // Flags (0x01)
    adv_data.push(0x02); // Length
    adv_data.push(0x01); // Flags type
    adv_data.push(0x06); // LE General Discoverable, BR/EDR not supported
    
    // Local name (0x09)
    let name = b"RustyBlue";
    adv_data.push(name.len() as u8 + 1); // Length
    adv_data.push(0x09); // Complete local name type
    adv_data.extend_from_slice(name);
    
    // 16-bit service UUIDs (0x03)
    adv_data.push(0x03); // Length
    adv_data.push(0x03); // Complete 16-bit service UUIDs
    adv_data.extend_from_slice(&custom_service_uuid.as_bytes());
    
    // Pad to 31 bytes
    while adv_data.len() < 31 {
        adv_data.push(0);
    }
    
    socket.send_command(&HciCommand::LeSetAdvertisingData {
        data: adv_data,
    })?;
    socket.read_event()?;
    
    // Enable advertising
    socket.send_command(&HciCommand::LeSetAdvertiseEnable {
        enable: 0x01, // Enable
    })?;
    socket.read_event()?;
    println!("Enabled LE advertising");
    
    // Update the custom characteristic value every 5 seconds
    let mut counter = 0u32;
    
    println!("Server is running. Press Ctrl+C to exit.");
    
    loop {
        // Process incoming events
        match socket.read_event_timeout(Some(Duration::from_secs(1))) {
            Ok(event) => {
                println!("Received event: {:?}", event);
                
                // Handle disconnection events
                if event.event_code == 0x05 { // Disconnection Complete
                    println!("Client disconnected");
                }
                
                // Handle connection events
                if event.event_code == 0x3E && event.parameters.len() > 0 && event.parameters[0] == 0x01 {
                    println!("Client connected");
                }
            },
            Err(_) => {
                // Timeout, update characteristic value
                counter += 1;
                let value = format!("Counter: {}", counter).into_bytes();
                
                if let Err(e) = gatt_server.update_characteristic(
                    custom_char_handle,
                    &value,
                    true, // Notify
                    false // Don't indicate
                ) {
                    println!("Failed to update characteristic: {:?}", e);
                } else {
                    println!("Updated characteristic value: Counter: {}", counter);
                }
                
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }
}