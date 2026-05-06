// Licensed under the Apache-2.0 license

//! SPDM VDM Validator Binary
//!
//! Connects to an SPDM bridge (SpdmValidatorRunner), establishes an SPDM
//! session, and runs Caliptra VDM command validations.
//!
//! Spawned as a subprocess by the integration test harness.

use anyhow::Result;
use caliptra_spdm_requester::{SpdmConfig, SpdmRequester, SpdmSocketDeviceIo, SpdmVdmDriverImpl};
use caliptra_spdm_vdm_client::config::{self, TestConfig};
use caliptra_spdm_vdm_client::{validator, SpdmVdmClient};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "caliptra-spdm-validator")]
#[command(about = "SPDM VDM Validator — tests Caliptra VDM commands over SPDM/MCTP")]
struct Args {
    /// Server address (host:port) of the SPDM bridge
    #[arg(long, default_value = "127.0.0.1:2323")]
    server: String,

    /// SPDM slot ID
    #[arg(long, default_value_t = 0)]
    slot_id: u8,

    /// Path to TOML configuration file (overrides CLI args)
    #[arg(long)]
    config: Option<String>,

    /// Key IDs to test for ExportAttestedCsr (comma-separated)
    #[arg(long)]
    key_ids: Option<String>,

    /// Algorithm ID for ExportAttestedCsr (1=EccP384, 2=MlDsa87)
    #[arg(long)]
    algorithm: Option<u32>,
}

impl Args {
    /// Build a TestConfig from CLI args, with TOML file as base when provided.
    fn into_config(self) -> Result<TestConfig> {
        let mut config = if let Some(config_path) = &self.config {
            TestConfig::from_file(std::path::Path::new(config_path))?
        } else {
            TestConfig {
                network: config::NetworkConfig {
                    server_address: self.server.clone(),
                },
                spdm: config::SpdmTestConfig {
                    slot_id: self.slot_id,
                },
                ..TestConfig::default()
            }
        };

        // CLI args override config file values when explicitly provided.
        if self.config.is_none() {
            config.network.server_address = self.server;
            config.spdm.slot_id = self.slot_id;
        }
        if let Some(key_ids) = &self.key_ids {
            config.export_attested_csr.key_ids = parse_key_ids(key_ids)?;
        }
        if let Some(algorithm) = self.algorithm {
            config.export_attested_csr.algorithm = algorithm;
        }

        Ok(config)
    }
}

fn main() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .ok();

    let config = Args::parse().into_config()?;

    println!(
        "[caliptra-spdm-validator] Connecting to bridge at {}",
        config.network.server_address
    );

    let mut device_io = SpdmSocketDeviceIo::connect_mctp(&config.network.server_address)?;
    device_io.handshake()?;
    println!("[caliptra-spdm-validator] Bridge handshake OK");

    let mut stop_io = device_io.try_clone()?;

    let spdm_config = SpdmConfig {
        slot_id: config.spdm.slot_id,
        ..SpdmConfig::default()
    };
    let mut requester = SpdmRequester::new(spdm_config, Box::new(device_io))?;

    println!("[caliptra-spdm-validator] Establishing SPDM connection...");
    requester.connect()?;
    println!("[caliptra-spdm-validator] SPDM connection established");

    let results = {
        let mut vdm = SpdmVdmDriverImpl::new(&mut requester, None);
        let mut client = SpdmVdmClient::new(&mut vdm);
        validator::run_all(&mut client, &config, true)
    };
    validator::print_summary(&results);

    println!("[caliptra-spdm-validator] Sending STOP to bridge");
    stop_io.send_stop()?;

    if validator::all_passed(&results) {
        Ok(())
    } else {
        anyhow::bail!("Some tests FAILED")
    }
}

fn parse_key_ids(s: &str) -> Result<Vec<u32>> {
    s.split(',')
        .map(|s| s.trim().parse::<u32>().map_err(Into::into))
        .collect()
}
