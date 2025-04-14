use rustyblue::{GattClient, HciSocket};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open the first HCI device
    println!("Opening HCI socket...");
    let socket = HciSocket::open(0)?;

    // Initialize GATT client
    println!("Initializing GATT client...");
    let mut client = GattClient::new(socket);

    // Scan for devices
    println!("Scanning for devices...");
    rustyblue::scan_le(&client.socket(), Duration::from_secs(5), |report| {
        println!(
            "Device found: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} (RSSI: {})",
            report.address[5],
            report.address[4],
            report.address[3],
            report.address[2],
            report.address[1],
            report.address[0],
            report.rssi
        );

        // Parse advertising data
        let ad_data = rustyblue::parse_advertising_data(&report.data);
        for (ad_type, data) in ad_data {
            if ad_type == 0x09 {
                // Complete Local Name
                if let Ok(name) = std::str::from_utf8(&data) {
                    println!("  Name: {}", name);
                }
            }
        }
    })?;

    // Ask user which device to connect to
    println!("\nEnter MAC address of device to connect to (format: XX:XX:XX:XX:XX:XX):");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let addr = input.trim();

    // Parse MAC address
    let bytes: Vec<u8> = addr
        .split(':')
        .map(|s| u8::from_str_radix(s, 16).unwrap_or(0))
        .collect();

    if bytes.len() != 6 {
        return Err("Invalid MAC address format".into());
    }

    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[5 - i] = bytes[i]; // Reverse order for little endian
    }

    // Connect to device
    println!("Connecting to device...");
    client.connect(mac, 0)?; // Assuming public address type

    // Discover services
    println!("Discovering services...");
    let services = client.discover_services()?;
    println!("Found {} services", services.len());

    // Clone services to avoid borrow issues
    let services_clone = services.to_vec();

    // Process each service
    for (i, service) in services_clone.iter().enumerate() {
        println!("Service {}: UUID = {}", i, service.uuid);

        // Discover characteristics for this service
        let characteristics = client.discover_characteristics(service)?;
        println!("  Found {} characteristics", characteristics.len());

        // Clone characteristics to avoid borrow issues
        let characteristics_clone = characteristics.to_vec();

        for (j, characteristic) in characteristics_clone.iter().enumerate() {
            println!("  Characteristic {}: UUID = {}", j, characteristic.uuid);

            // Read characteristic if it's readable
            if characteristic.properties.can_read() {
                match client.read_characteristic(characteristic) {
                    Ok(data) => {
                        println!("    Value: {:?}", data);
                    }
                    Err(e) => {
                        println!("    Failed to read: {}", e);
                    }
                }
            }
        }
    }

    // Disconnect
    println!("Disconnecting...");
    client.disconnect()?;

    println!("Done!");
    Ok(())
}
