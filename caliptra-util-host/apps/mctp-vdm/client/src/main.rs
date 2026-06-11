// Licensed under the Apache-2.0 license

//! MCTP VDM Client Binary
//!
//! Command-line tool that talks to a Caliptra device over the I3C controller
//! socket exposed by the emulator. Supports validating VDM communication and
//! retrieving + decoding the device debug log.

use anyhow::Result;
use caliptra_mcu_core_mctp_vdm_client::{
    decode_defmt_stream, DynamicI3cAddress, MctpVdmSocketDriver, TestConfig, Validator, VdmClient,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "mctp-vdm-client")]
#[command(about = "Communicates with a Caliptra device over MCTP VDM")]
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

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Validate VDM communication with the device (default).
    Validate {
        /// Path to TOML configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Retrieve the device debug log and decode it against a firmware ELF.
    GetLog {
        /// Path to the user-app ELF containing the `.defmt` table.
        #[arg(short, long)]
        elf: PathBuf,

        /// Emit decoded messages as JSON instead of plain text.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Some(Command::GetLog { elf, json }) => run_get_log(args.port, args.target_addr, &elf, json),
        Some(Command::Validate { config }) => {
            run_validate(args.port, args.target_addr, args.verbose, config)
        }
        None => run_validate(args.port, args.target_addr, args.verbose, None),
    }
}

fn run_validate(port: u16, target_addr: u8, verbose: bool, config: Option<PathBuf>) -> Result<()> {
    println!("Caliptra MCTP VDM Client Validator");
    println!("==================================\n");

    let validator = if let Some(config_path) = config {
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
                println!("Connecting to port {} target 0x{:02X}", port, target_addr);
                let config = TestConfig {
                    network: caliptra_mcu_core_mctp_vdm_client::NetworkConfig {
                        default_server_address: format!("127.0.0.1:{}", port),
                        target_i3c_address: target_addr,
                    },
                    ..TestConfig::default()
                };
                Validator::new(&config)?
            }
        }
    }
    .set_verbose(verbose);

    if verbose {
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

fn run_get_log(port: u16, target_addr: u8, elf: &PathBuf, json: bool) -> Result<()> {
    let elf_bytes =
        std::fs::read(elf).map_err(|e| anyhow::anyhow!("failed to read ELF {:?}: {e}", elf))?;

    let mut driver = MctpVdmSocketDriver::new(port, DynamicI3cAddress::from(target_addr));
    let mut client = VdmClient::new(&mut driver);
    client.connect()?;
    let log_bytes = client.drain_debug_log()?;
    client.disconnect().ok();

    if log_bytes.is_empty() {
        eprintln!("Device returned no debug log data.");
        return Ok(());
    }

    let messages = decode_defmt_stream(&elf_bytes, &log_bytes)?;

    if json {
        let body = messages
            .iter()
            .map(|m| json_escape(m))
            .collect::<Vec<_>>()
            .join(",");
        println!("[{}]", body);
    } else {
        for m in &messages {
            println!("{m}");
        }
    }

    Ok(())
}

/// Minimal JSON string escaping for a decoded message (avoids a serde dep here).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
