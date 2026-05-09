// Licensed under the Apache-2.0 license

//! Caliptra Mailbox Server Library
//!
//! This library provides a synchronous UDP server that receives raw command bytes
//! and passes them to a handler function for processing.

use anyhow::{Context, Result};
use caliptra_util_host_mailbox_test_config::TestConfig;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Configuration for the mailbox server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub timeout: Option<Duration>,
    pub buffer_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:62222".parse().unwrap(),
            timeout: Some(Duration::from_secs(30)),
            buffer_size: 4096,
        }
    }
}

impl ServerConfig {
    /// Create ServerConfig from shared TestConfig
    pub fn from_test_config(config: &TestConfig) -> Result<Self> {
        let bind_addr: SocketAddr = config
            .server
            .bind_address
            .parse()
            .with_context(|| "Invalid bind address in config")?;

        Ok(Self {
            bind_addr,
            timeout: Some(Duration::from_secs(config.validation.timeout_seconds)),
            buffer_size: 4096,
        })
    }
}

/// Handler function type for processing commands
/// Takes raw command bytes and returns raw response bytes
pub type CommandHandler = dyn Fn(&[u8]) -> Result<Vec<u8>>;

/// Synchronous UDP-based Mailbox Server
pub struct MailboxServer {
    socket: UdpSocket,
    #[allow(dead_code)] // Reserved for future use
    config: ServerConfig,
    buffer: Vec<u8>,
}

impl MailboxServer {
    /// Create a new mailbox server with the given configuration
    pub fn new(config: ServerConfig) -> Result<Self> {
        let socket = UdpSocket::bind(config.bind_addr)
            .with_context(|| format!("Failed to bind to {}", config.bind_addr))?;

        if let Some(timeout) = config.timeout {
            socket
                .set_read_timeout(Some(timeout))
                .context("Failed to set read timeout")?;
            socket
                .set_write_timeout(Some(timeout))
                .context("Failed to set write timeout")?;
        }

        println!("Mailbox server listening on {}", config.bind_addr);

        Ok(Self {
            socket,
            buffer: vec![0u8; config.buffer_size],
            config,
        })
    }

    /// Run the server with the provided command handler
    /// This function blocks and handles incoming requests
    pub fn run<F>(&mut self, handler: F) -> Result<()>
    where
        F: Fn(&[u8]) -> Result<Vec<u8>>,
    {
        println!("Server started, waiting for commands...");

        loop {
            match self.handle_request(&handler) {
                Ok(_) => {
                    // Continue serving
                }
                Err(e) => {
                    eprintln!("Error handling request: {}", e);
                    // Continue serving despite errors
                }
            }
        }
    }

    /// Handle a single request
    fn handle_request<F>(&mut self, handler: &F) -> Result<()>
    where
        F: Fn(&[u8]) -> Result<Vec<u8>>,
    {
        // Receive command from client
        let (bytes_received, client_addr) = self
            .socket
            .recv_from(&mut self.buffer)
            .context("Failed to receive data")?;

        println!("Received {} bytes from {}", bytes_received, client_addr);

        // Process the command with the provided handler
        let command_data = &self.buffer[..bytes_received];
        let response_data = match handler(command_data) {
            Ok(response) => response,
            Err(e) => {
                eprintln!("Command handler failed: {}", e);
                // Return a simple error response
                vec![0xFF] // Generic error
            }
        };

        // Send response back to client
        self.socket
            .send_to(&response_data, client_addr)
            .with_context(|| format!("Failed to send response to {}", client_addr))?;

        println!(
            "Sent {} byte response to {}",
            response_data.len(),
            client_addr
        );

        Ok(())
    }

    /// Get the local address the server is bound to
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .context("Failed to get local address")
    }
}
