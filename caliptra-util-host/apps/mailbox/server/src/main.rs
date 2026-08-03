// Licensed under the Apache-2.0 license

//! Caliptra Mailbox Server Binary
//!
//! A simple server that receives raw command bytes and echoes them back
//! or provides basic command responses emulating a Caliptra device.

use anyhow::{Context, Result};
use caliptra_mcu_core_mailbox_server::{MailboxServer, ServerConfig};
use caliptra_mcu_core_util_host_mailbox_test_config::TestConfig;
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
                // GetDeviceCapabilities external mailbox command ("MCAP")
                0x4D434150 => {
                    println!("✓ MATCHED GetDeviceCapabilities command (MCAP)!");

                    // Create proper external mailbox response format for GetDeviceCapabilities
                    // Following the MockMailbox format: checksum + fips_status + 32-byte caps array
                    // Response structure:
                    // - chksum: u32 (4 bytes)
                    // - fips_status: u32 (4 bytes)
                    // - caps_array: [u8; 32] (32 bytes containing structured capability data)
                    // Total: 40 bytes

                    let mut response = vec![0u8; 40];

                    // Use config values if available, otherwise fallback defaults
                    let (fips_status, capabilities, max_cert_size, max_csr_size, device_lifecycle) =
                        if let Some(ref config) = test_config {
                            if let Some(ref caps_config) = config.device_capabilities {
                                (
                                    caps_config.fips_status,
                                    caps_config.capabilities,
                                    caps_config.max_cert_size,
                                    caps_config.max_csr_size,
                                    caps_config.device_lifecycle,
                                )
                            } else {
                                (0x00000001u32, 0x000001F3u32, 4096u32, 2048u32, 1u32)
                            }
                        } else {
                            (0x00000001u32, 0x000001F3u32, 4096u32, 2048u32, 1u32)
                        };

                    // Build 32-byte caps array matching MockMailbox format
                    let mut caps = [0u8; 32];
                    caps[0..4].copy_from_slice(&capabilities.to_le_bytes());
                    caps[4..8].copy_from_slice(&max_cert_size.to_le_bytes());
                    caps[8..12].copy_from_slice(&max_csr_size.to_le_bytes());
                    caps[12..16].copy_from_slice(&device_lifecycle.to_le_bytes());

                    // Fill response data (excluding checksum)
                    response[4..8].copy_from_slice(&fips_status.to_le_bytes());
                    response[8..40].copy_from_slice(&caps);

                    // Calculate checksum on payload only
                    let payload = &response[4..40];
                    let mut sum = 0u32;
                    for byte in payload.iter() {
                        sum = sum.wrapping_add(*byte as u32);
                    }
                    let checksum = 0u32.wrapping_sub(sum);
                    response[0..4].copy_from_slice(&checksum.to_le_bytes());

                    println!(
                        "Generated GetDeviceCapabilities response: {} bytes",
                        response.len()
                    );
                    Ok(response)
                }
                // GetFirmwareVersion external mailbox command ("MFWV")
                0x4D465756 => {
                    println!("✓ MATCHED GetFirmwareVersion command (MFWV)!");

                    // Create proper external mailbox response format for GetFirmwareVersion
                    // Variable-size format: checksum + fips_status + data_len + version_data
                    // Response structure:
                    // - chksum: u32 (4 bytes)
                    // - fips_status: u32 (4 bytes)
                    // - data_len: u32 (4 bytes)
                    // - version_data: variable length data

                    // Use config values if available, otherwise fallback defaults
                    let (fips_status, version_str) = if let Some(ref config) = test_config {
                        if let Some(ref fw_config) = config.firmware_version {
                            (fw_config.fips_status, fw_config.rom_version.as_bytes())
                        } else {
                            (0x00000001u32, b"1.2.3.4567-mock_commit_hash" as &[u8])
                        }
                    } else {
                        (0x00000001u32, b"1.2.3.4567-mock_commit_hash" as &[u8])
                    };

                    let data_len = version_str.len() as u32;
                    let response_size = 12 + version_str.len(); // 12 bytes header + data
                    let mut response = vec![0u8; response_size];

                    // Fill response data (excluding checksum)
                    response[4..8].copy_from_slice(&fips_status.to_le_bytes());
                    response[8..12].copy_from_slice(&data_len.to_le_bytes());
                    response[12..12 + version_str.len()].copy_from_slice(version_str);

                    // Calculate checksum on payload only (excluding checksum field)
                    let payload = &response[4..];
                    let mut sum = 0u32;
                    for byte in payload.iter() {
                        sum = sum.wrapping_add(*byte as u32);
                    }
                    let checksum = 0u32.wrapping_sub(sum);
                    response[0..4].copy_from_slice(&checksum.to_le_bytes());

                    println!(
                        "Generated GetFirmwareVersion response: {} bytes",
                        response.len()
                    );
                    Ok(response)
                }

                _ => {
                    println!("✗ Unknown command type: 0x{:08x}", cmd_type);
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
