// Licensed under the Apache-2.0 license

//! Caliptra Mailbox Client Validator Binary
//!
//! This binary provides a command-line interface for validating communication
//! with Caliptra mailbox servers using the caliptra-mailbox-client library.

use anyhow::Result;
use caliptra_mailbox_client::{TestConfig, Validator};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "validator")]
#[command(
    about = "Caliptra mailbox client validator - validates communication with a Caliptra mailbox server"
)]
#[command(version)]
struct Args {
    /// Server address to connect to
    #[arg(
        short,
        long,
        default_value = "127.0.0.1:62222",
        help = "Server socket address (host:port)"
    )]
    server: SocketAddr,

    /// Enable verbose output
    #[arg(
        short,
        long,
        help = "Enable verbose output showing detailed test results"
    )]
    verbose: bool,

    /// Configuration file path
    #[arg(
        short,
        long,
        help = "Path to TOML configuration file with test parameters"
    )]
    config: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Caliptra Mailbox Client Validator");
    println!("=================================\n");

    // Create validator based on config file or command line args
    let validator = if let Some(config_path) = args.config {
        println!("Loading configuration from: {:?}", config_path);
        let config = TestConfig::from_file(&config_path)?;
        Validator::from_config(&config)?
    } else {
        // Try to load default config, but override server with command line if provided
        match TestConfig::load_default() {
            Ok(config) => {
                println!("Using default configuration file");
                let mut validator = Validator::from_config(&config)?;
                // Override server address if different from default
                if args.server.to_string() != "127.0.0.1:8080" {
                    println!("Overriding config server address with: {}", args.server);
                    validator = Validator::new(args.server);
                }
                validator
            }
            Err(_) => {
                println!("No configuration file found, using command line arguments");
                println!("Connecting to server: {}", args.server);
                Validator::new(args.server)
            }
        }
    }
    .set_verbose(args.verbose);

    if args.verbose {
        println!("Verbose mode: enabled\n");
    }

    // Run validation
    let results = validator.start()?;
    let success = results.iter().all(|r| r.passed);

    if success {
        println!("\n✓ All validation tests passed!");
        std::process::exit(0);
    } else {
        println!("\n✗ Some validation tests failed!");
        std::process::exit(1);
    }
}
