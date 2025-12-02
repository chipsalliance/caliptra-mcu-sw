// Licensed under the Apache-2.0 license

//! Caliptra Mailbox Server Binary
//!
//! A simple server that receives raw command bytes and echoes them back
//! or provides basic command responses emulating a Caliptra device.

use anyhow::{Context, Result};
use caliptra_mailbox_server::{MailboxServer, ServerConfig};
use caliptra_util_host_mailbox_test_config::TestConfig;
use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser)]
#[command(name = "caliptra-mailbox-server")]
#[command(about = "A mailbox server that emulates Caliptra device responses")]
struct Args {
    /// Server socket address (host:port)
    #[arg(short, long, default_value = "127.0.0.1:62222")]
    server: String,

    /// Path to TOML configuration file with device parameters
    #[arg(short, long)]
    config: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration if provided, otherwise try to load default
    let test_config = if let Some(config_path) = &args.config {
        Some(TestConfig::from_file(config_path)?)
    } else {
        // Try to load default config, fall back to None if not found
        TestConfig::load_default().ok()
    };

    // Parse server address
    let bind_addr: SocketAddr = args.server.parse().context("Invalid socket address")?;

    let config = ServerConfig {
        bind_addr,
        ..Default::default()
    };

    let mut server = MailboxServer::new(config)?;

    println!("Starting mailbox server on {}", bind_addr);
    println!("Server will echo back received commands");
    println!("Press Ctrl+C to stop");

    // Run server with a simple echo handler
    server.run(|raw_bytes| {
        println!("Received command: {} bytes", raw_bytes.len());

        // For demonstration, we'll handle some basic commands
        if raw_bytes.len() >= 4 {
            // Check if this looks like a mailbox command header
            let cmd_type =
                u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]);

            println!(
                "Raw bytes: {:02X} {:02X} {:02X} {:02X}",
                raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]
            );
            println!("Parsed command type: 0x{:08X}", cmd_type);

            match cmd_type {
                // GetDeviceId external mailbox command ("MDID")
                0x4D444944 => {
                    println!("✓ MATCHED GetDeviceId command (MDID)!");

                    // Create proper external mailbox response format for GetDeviceId
                    // Based on ExtCmdGetDeviceIdResponse structure:
                    // - chksum: u32 (4 bytes)
                    // - fips_status: u32 (4 bytes)
                    // - vendor_id: u16 (2 bytes)
                    // - device_id: u16 (2 bytes)
                    // - subsystem_vendor_id: u16 (2 bytes)
                    // - subsystem_id: u16 (2 bytes)
                    // Total: 16 bytes

                    let mut response = vec![0u8; 16];

                    // First build the data part without checksum
                    let fips_status = 0u32; // Success/FIPS approved

                    // Use config values if available, otherwise fallback defaults
                    let (vendor_id, device_id, subsystem_vendor_id, subsystem_id) =
                        if let Some(ref config) = test_config {
                            (
                                config.device.vendor_id,
                                config.device.device_id,
                                config.device.subsystem_vendor_id,
                                config.device.subsystem_id,
                            )
                        } else {
                            (0x5678u16, 0x1234u16, 0x0000u16, 0x0000u16) // Fallback values
                        };

                    // Fill response data (excluding checksum at start)
                    response[4..8].copy_from_slice(&fips_status.to_le_bytes());
                    response[8..10].copy_from_slice(&vendor_id.to_le_bytes());
                    response[10..12].copy_from_slice(&device_id.to_le_bytes());
                    response[12..14].copy_from_slice(&subsystem_vendor_id.to_le_bytes());
                    response[14..16].copy_from_slice(&subsystem_id.to_le_bytes());

                    // Calculate checksum for response data (excluding checksum field)
                    // For responses, use cmd = 0 in checksum calculation
                    let data_part = &response[4..16]; // Everything except the checksum field

                    // Checksum formula: 0 - (SUM(cmd=0 bytes) + SUM(response bytes))
                    let mut sum = 0u32;
                    // For responses, cmd = 0, so no command bytes to add
                    for byte in data_part.iter() {
                        sum = sum.wrapping_add(*byte as u32);
                    }
                    let checksum = 0u32.wrapping_sub(sum);

                    // Set the checksum at the beginning
                    response[0..4].copy_from_slice(&checksum.to_le_bytes());

                    println!("Generated GetDeviceId response: {} bytes", response.len());
                    println!("Response bytes: {:02X?}", response);
                    println!("Checksum: 0x{:08X}", checksum);

                    Ok(response)
                }
                // GetFirmwareVersion external mailbox command ("MFWV")
                0x4D465756 => {
                    println!("Handling GetFirmwareVersion command (MFWV)");
                    let mut response = vec![0u8; 16];
                    response[0..4].copy_from_slice(&0x4D465756u32.to_le_bytes()); // Command echo
                    response[4..8].copy_from_slice(&0u32.to_le_bytes()); // Success status
                    response[8..12].copy_from_slice(&0x00010002u32.to_le_bytes()); // Mock version
                    Ok(response)
                }
                // GetDeviceCapabilities external mailbox command ("MCAP")
                0x4D434150 => {
                    println!("Handling GetDeviceCapabilities command (MCAP)");
                    let mut response = vec![0u8; 16];
                    response[0..4].copy_from_slice(&0x4D434150u32.to_le_bytes()); // Command echo
                    response[4..8].copy_from_slice(&0u32.to_le_bytes()); // Success status
                    response[8..12].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // Mock capabilities
                    Ok(response)
                }
                _ => {
                    println!(
                        "✗ Unknown command type: 0x{:08x} (expected 0x{:08x})",
                        cmd_type, 0x4D444944u32
                    );
                    println!("✗ Comparison result: {}", cmd_type == 0x4D444944u32);
                    // Echo back the command
                    Ok(raw_bytes.to_vec())
                }
            }
        } else {
            println!("Command too short, echoing back");
            // Just echo back short commands
            Ok(raw_bytes.to_vec())
        }
    })
}
