use rustyblue::{SdpClient, Uuid};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Create an SDP client
    let mut client = SdpClient::new();
    
    // Connect to SDP service
    println!("Connecting to SDP service...");
    client.connect()?;
    
    // Define service UUIDs to search for
    // Searching for SPP (Serial Port Profile) as an example
    let spp_uuid = rustyblue::sdp::Uuid::Uuid16(0x1101);
    
    // Discover services
    println!("Discovering services...");
    let services = client.discover_services(&[spp_uuid])?;
    
    // Print found services
    println!("Found {} services", services.len());
    for service in services {
        println!("Service handle: 0x{:08X}", service.handle);
        println!("Service class IDs:");
        for uuid in &service.service_class_id_list {
            match uuid {
                rustyblue::sdp::Uuid::Uuid16(uuid) => println!("  16-bit UUID: 0x{:04X}", uuid),
                rustyblue::sdp::Uuid::Uuid32(uuid) => println!("  32-bit UUID: 0x{:08X}", uuid),
                rustyblue::sdp::Uuid::Uuid128(uuid) => println!("  128-bit UUID: {:?}", uuid),
            }
        }
        println!("Attributes:");
        for (id, value) in &service.attributes {
            println!("  Attribute ID: 0x{:04X}", id);
            println!("  Value: {:?}", value);
        }
        println!();
    }
    
    // Disconnect
    client.disconnect()?;
    
    Ok(())
}