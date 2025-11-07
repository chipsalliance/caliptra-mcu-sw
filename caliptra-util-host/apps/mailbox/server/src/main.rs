// Licensed under the Apache-2.0 license

//! Caliptra Mailbox Server Binary
//!
//! A simple server that receives raw command bytes and echoes them back
//! or provides basic command responses.

use anyhow::{Context, Result};
use caliptra_mailbox_server::{MailboxServer, ServerConfig};
use std::net::SocketAddr;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Parse command line arguments
    let bind_addr = if args.len() > 1 {
        args[1]
            .parse::<SocketAddr>()
            .context("Invalid socket address")?
    } else {
        "127.0.0.1:8080".parse().unwrap()
    };

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

            match cmd_type {
                // If it's a GetDeviceId command (assuming command type 1)
                1 => {
                    println!("Handling GetDeviceId command");
                    // Return a mock device ID response
                    let mut response = vec![0u8; 8]; // 8 bytes for mock response
                    response[0..4].copy_from_slice(&1u32.to_le_bytes()); // Success status
                    response[4..8].copy_from_slice(&0x12345678u32.to_le_bytes()); // Mock device ID
                    Ok(response)
                }
                _ => {
                    println!("Unknown command type: 0x{:08x}", cmd_type);
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
