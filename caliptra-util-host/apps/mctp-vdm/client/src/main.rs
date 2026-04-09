// Licensed under the Apache-2.0 license

//! MCTP VDM Client Validator Binary
//!
//! Command-line tool that validates VDM communication with a Caliptra device
//! via the I3C controller socket exposed by the emulator.

use anyhow::Result;
use caliptra_mcu_core_mctp_vdm_client::{TestConfig, Validator};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "mctp-vdm-validator")]
#[command(about = "Validates MCTP VDM communication with a Caliptra device")]
#[command(version)]
struct Args {
    /// I3C controller socket port
    #[arg(short = 'p', long, default_value = "63333")]
    port: u16,

    /// I3C dynamic target address (hex)
    #[arg(short = 'a', long, default_value = "8")]
    target_addr: u8,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Path to TOML configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Caliptra MCTP VDM Client Validator");
    println!("==================================\n");

    let validator = if let Some(config_path) = args.config {
        println!("Loading configuration from: {:?}", config_path);
        let config = TestConfig::from_file(&config_path)?;
        Validator::new(&config)?
    } else {
        match TestConfig::load_default() {
            Ok(config) => {
                println!("Using default configuration file");
                Validator::new(&config)?
            }
            Err(_) => {
                println!("No configuration file found, using command line arguments");
                println!(
                    "Connecting to port {} target 0x{:02X}",
                    args.port, args.target_addr
                );
                let config = TestConfig {
                    network: caliptra_mcu_core_mctp_vdm_client::NetworkConfig {
                        default_server_address: format!("127.0.0.1:{}", args.port),
                        target_i3c_address: args.target_addr,
                    },
                    ..TestConfig::default()
                };
                Validator::new(&config)?
            }
        }
    }
    .set_verbose(args.verbose);

    if args.verbose {
        println!("Verbose mode: enabled\n");
    }

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
