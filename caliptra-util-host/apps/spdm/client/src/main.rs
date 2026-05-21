// Licensed under the Apache-2.0 license

//! SPDM VDM Validator Binary
//!
//! Connects to an SPDM bridge (SpdmValidatorRunner), establishes an SPDM
//! session, and runs Caliptra VDM command validations.
//!
//! Spawned as a subprocess by the integration test harness.

use anyhow::Result;
use caliptra_spdm_requester::{SpdmConfig, SpdmRequester, SpdmSocketDeviceIo, SpdmVdmDriverImpl};
use caliptra_spdm_vdm_client::config::{self, DeviceMode, TestConfig};
use caliptra_spdm_vdm_client::{
    validator, CommandAuthorizer, DebugUnlockKeys, DebugUnlockSigner, HmacCommandAuthorizer,
    LocalDebugUnlockSigner, SpdmVdmClient,
};
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

    /// Device mode: production or manufacturing
    #[arg(long, value_enum, default_value_t = DeviceMode::Production)]
    mode: DeviceMode,

    /// Key IDs to test for ExportAttestedCsr (comma-separated)
    #[arg(long)]
    key_ids: Option<String>,

    /// Algorithm ID for ExportAttestedCsr (1=EccP384, 2=MlDsa87)
    #[arg(long)]
    algorithm: Option<u32>,
    /// Algorithm IDs for ExportIdevidCsr (comma-separated)
    #[arg(long)]
    idevid_algorithms: Option<String>,

    /// Path to a binary file containing debug unlock keys (written by DebugUnlockKeys::save_to_file)
    #[arg(long)]
    debug_unlock_keys_file: Option<String>,

    /// Debug unlock level (1-8)
    #[arg(long)]
    unlock_level: Option<u8>,
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
                mode: self.mode,
                ..TestConfig::default()
            }
        };

        // CLI args always override config file values for server and mode.
        config.network.server_address = self.server;
        config.spdm.slot_id = self.slot_id;
        config.mode = self.mode;
        if let Some(key_ids) = &self.key_ids {
            config.export_attested_csr.key_ids = parse_key_ids(key_ids)?;
        }
        if let Some(algorithm) = self.algorithm {
            config.export_attested_csr.algorithm = algorithm;
        }
        if let Some(algorithms) = &self.idevid_algorithms {
            config.export_idevid_csr.algorithms = parse_key_ids(algorithms)?;
        }
        if let Some(unlock_level) = self.unlock_level {
            config.debug_unlock.unlock_level = unlock_level;
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

    let args = Args::parse();
    let debug_unlock_signer: Option<Box<dyn DebugUnlockSigner>> =
        if let Some(keys_path) = &args.debug_unlock_keys_file {
            let keys = DebugUnlockKeys::load_from_file(std::path::Path::new(keys_path))?;
            println!(
                "[caliptra-spdm-validator] Loaded debug unlock keys from {}",
                keys_path
            );
            Some(Box::new(LocalDebugUnlockSigner::new(keys)))
        } else {
            None
        };
    let config = args.into_config()?;

    let fe_prog_authorizer: Option<Box<dyn CommandAuthorizer>> =
        if let Some(hex_key) = &config.fe_prog.auth_key {
            let key = hex::decode(hex_key)?;
            Some(Box::new(HmacCommandAuthorizer::new(key)))
        } else {
            None
        };

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
        validator::run_all(
            &mut client,
            &config,
            debug_unlock_signer.as_deref(),
            fe_prog_authorizer.as_deref(),
            true,
        )
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
