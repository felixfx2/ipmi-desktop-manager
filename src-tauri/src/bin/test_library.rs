use ipmi_desktop_manager_lib::ipmi::IpmiClient;

#[tokio::main]
async fn main() {
    env_logger::init();
    println!("=== IpmiClient Multi-Command Test ===");
    println!("Target: 10.2.1.10:623");
    println!("User: 'opencode' Pass: 'S8008078f!'");
    println!();

    let mut client = IpmiClient::new();
    match client.connect("10.2.1.10", 623, "opencode", "S8008078f!").await {
        Ok(()) => {
            println!("LOGIN: SUCCESS!\n");

            // Try commands in different order to find what works
            let commands: Vec<(&str, u8, u8, Vec<u8>)> = vec![
                ("Get Auth Capabilities ch=0x0E", 0x06, 0x38, vec![0x0E, 0x04]),
                ("Get Auth Capabilities ch=0x00", 0x06, 0x38, vec![0x00, 0x04]),
                ("Get Auth Capabilities ch=0x01", 0x06, 0x38, vec![0x01, 0x04]),
                ("Get Device ID", 0x06, 0x01, vec![]),
                ("Get Channel Auth Cap ch=0x0E", 0x06, 0x38, vec![0x0E, 0x04]),
                ("Get Session Info", 0x06, 0x3D, vec![0x00]),
                ("Set Session Priv Level (Admin=0x04)", 0x06, 0x3B, vec![0x04]),
                ("Get Device ID (retry)", 0x06, 0x01, vec![]),
                ("Get Channel Info ch=0x00", 0x06, 0x52, vec![0x00]),
                ("Get Channel Info ch=0x01", 0x06, 0x52, vec![0x01]),
                ("Get Channel Info ch=0x08", 0x06, 0x52, vec![0x08]),
                ("Chassis Status (netfn=0x00)", 0x00, 0x01, vec![]),
                ("Chassis Control Power On rq_lun=0", 0x00, 0x02, vec![0x01]),
            ];

            // Test Chassis Control directly with raw IPMI to check rq_lun
            println!("\n--- Direct Chassis Control tests ---");
            for data_val in [0x00u8, 0x01, 0x02, 0x03] {
                let name = match data_val {
                    0x00 => "Power Off",
                    0x01 => "Power On",
                    0x02 => "Power Cycle",
                    0x03 => "Hard Reset",
                    _ => "Unknown",
                };
                print!("  Chassis Control 0x{:02x} ({:15}) -> ", data_val, name);
                match client.send_ipmi_command(0x00, 0x02, &[data_val]).await {
                    Ok(resp) => println!("OK ({}) {:02x?}", resp.len(), resp),
                    Err(e) => println!("{:?}", e),
                }
            }

            // Test with netfn=0x00 cmd=0x00 (Get Chassis Capabilities)
            print!("  Get Chassis Capabilities (cmd=0x00)   -> ");
            match client.send_ipmi_command(0x00, 0x00, &[]).await {
                Ok(resp) => println!("OK ({}) {:02x?}", resp.len(), resp),
                Err(e) => println!("{:?}", e),
            }

            for (name, netfn, cmd, data) in &commands {
                print!("  {:40} -> ", name);
                match client.send_ipmi_command(*netfn, *cmd, data).await {
                    Ok(resp) => println!("OK ({}) {:02x?}", resp.len(), resp),
                    Err(e) => println!("{:?}", e),
                }
            }

            println!("\nClosing session...");
            match client.disconnect().await {
                Ok(()) => println!("Session closed cleanly"),
                Err(e) => println!("Close session error: {:?}", e),
            }
        }
        Err(e) => {
            println!("LOGIN: FAILED - {:?}", e);
        }
    }
}
