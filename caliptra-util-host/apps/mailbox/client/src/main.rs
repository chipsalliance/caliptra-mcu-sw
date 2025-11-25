// Licensed under the Apache-2.0 license

//! Caliptra Mailbox Client Validator Binary
//!
//! This binary provides a command-line interface for validating communication
//! with Caliptra mailbox servers using the caliptra-mailbox-client library.

use anyhow::Result;
use caliptra_mailbox_client::{run_basic_validation, run_verbose_validation};
use clap::Parser;
use std::net::SocketAddr;

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
        default_value = "127.0.0.1:8080",
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
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Caliptra Mailbox Client Validator");
    println!("=================================\n");
    println!("Connecting to server: {}", args.server);

    if args.verbose {
        println!("Verbose mode: enabled\n");
    }

    // Run validation
    let success = if args.verbose {
        run_verbose_validation(args.server)?
    } else {
        run_basic_validation(args.server)?
    };

    if success {
        println!("\n✓ All validation tests passed!");
        std::process::exit(0);
    } else {
        println!("\n✗ Some validation tests failed!");
        std::process::exit(1);
    }
}
