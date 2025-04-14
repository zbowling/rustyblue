use rustyblue::{Device, GapAdapter};
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn main() -> Result<(), Box<dyn Error>> {
    // Create a GAP adapter
    let mut adapter = GapAdapter::new(0)?;

    // Get the local device name and address
    let name = adapter.get_local_name()?;
    let address = adapter.get_local_address()?;

    println!("Local device: {} ({})", name, address);

    // Track discovered devices
    let devices = Arc::new(Mutex::new(Vec::new()));
    let devices_clone = devices.clone();

    // Callback for device discovery
    let callback = Box::new(move |device: &Device| {
        println!("Discovered device: {}", device.address);
        if let Some(name) = &device.name {
            println!("  Name: {}", name);
        }
        if let Some(rssi) = device.rssi {
            println!("  RSSI: {} dBm", rssi);
        }

        // Add or update device in our list
        let mut devices_guard = devices_clone.lock().unwrap();
        if !devices_guard
            .iter()
            .any(|d: &Device| d.address == device.address)
        {
            devices_guard.push(device.clone());
        }
    });

    // Start discovery
    println!("Starting device discovery...");
    adapter.start_discovery(callback)?;

    // Run discovery for 10 seconds
    for i in 0..10 {
        println!("Scanning... {}/10", i + 1);
        adapter.process_events(Some(Duration::from_secs(1)))?;
    }

    // Stop discovery
    adapter.stop_discovery()?;
    println!("Discovery stopped");

    // Print summary
    let devices_guard = devices.lock().unwrap();
    println!("\nDiscovered {} device(s):", devices_guard.len());

    for (i, device) in devices_guard.iter().enumerate() {
        println!(
            "{}. {} - Type: {:?}",
            i + 1,
            device.address,
            device.address_type
        );
        if let Some(name) = &device.name {
            println!("   Name: {}", name);
        }
        if let Some(rssi) = device.rssi {
            println!("   RSSI: {} dBm", rssi);
        }
        if let Some(tx_power) = device.tx_power {
            println!("   TX Power: {} dBm", tx_power);
        }
        if !device.service_uuids.is_empty() {
            println!("   Service UUIDs: {:?}", device.service_uuids);
        }
        println!();
    }

    Ok(())
}
