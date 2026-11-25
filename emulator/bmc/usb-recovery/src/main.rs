// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use caliptra_mcu_usb_recovery::libusb::{DeviceSelector, LibusbTransport};
use caliptra_mcu_usb_recovery::{RecoveryAgent, RecoveryImages, RecoveryOptions, RecoveryOutcome};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(about = "OCP USB recovery agent (Linux owns enumeration)")]
struct Args {
    #[arg(long, value_parser = clap_num::maybe_hex::<u16>)]
    vid: u16,
    #[arg(long, value_parser = clap_num::maybe_hex::<u16>)]
    pid: u16,
    #[arg(long)]
    bus: Option<u8>,
    #[arg(long)]
    address: Option<u8>,
    #[arg(long, default_value_t = 0)]
    cms: u8,
    #[arg(long, default_value_t = 2000, value_parser = clap::value_parser!(u64).range(1..))]
    transfer_timeout_ms: u64,
    #[arg(long, default_value_t = 30000, value_parser = clap::value_parser!(u64).range(1..))]
    progress_timeout_ms: u64,
    #[arg(long, default_value_t = 180000, value_parser = clap::value_parser!(u64).range(1..))]
    overall_timeout_ms: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read capabilities/status without changing recovery state.
    Probe,
    /// Transfer the device-requested images and await confirmed recovery success.
    Recover {
        #[arg(long)]
        caliptra_fmc_rt: PathBuf,
        #[arg(long)]
        soc_manifest: PathBuf,
        #[arg(long)]
        mcu_runtime: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    let images = match &args.command {
        Command::Recover {
            caliptra_fmc_rt,
            soc_manifest,
            mcu_runtime,
        } => Some((
            std::fs::read(caliptra_fmc_rt)
                .with_context(|| format!("read {}", caliptra_fmc_rt.display()))?,
            std::fs::read(soc_manifest)
                .with_context(|| format!("read {}", soc_manifest.display()))?,
            std::fs::read(mcu_runtime)
                .with_context(|| format!("read {}", mcu_runtime.display()))?,
        )),
        Command::Probe => None,
    };
    let transport = LibusbTransport::open(DeviceSelector {
        vendor_id: args.vid,
        product_id: args.pid,
        bus: args.bus,
        address: args.address,
    })?;
    let mut agent = RecoveryAgent::new(
        transport,
        RecoveryOptions {
            cms: args.cms,
            transfer_timeout: Duration::from_millis(args.transfer_timeout_ms),
            progress_timeout: Duration::from_millis(args.progress_timeout_ms),
            overall_timeout: Duration::from_millis(args.overall_timeout_ms),
            ..Default::default()
        },
    )?;
    let result = if let Some((caliptra_fmc_rt, soc_manifest, mcu_runtime)) = &images {
        agent
            .run(&RecoveryImages {
                caliptra_fmc_rt,
                soc_manifest,
                mcu_runtime,
            })
            .map(|outcome| match outcome {
                RecoveryOutcome::Confirmed => {
                    println!("Recovery success confirmed by device status")
                }
                RecoveryOutcome::AlreadyRunning => {
                    println!("Device already running recovery; no images transferred")
                }
            })
    } else {
        agent.probe().map(|discovery| {
            println!(
                "OCP Recovery {}.{}; CMS regions: {}; device status: {:?}",
                discovery.capabilities.major,
                discovery.capabilities.minor,
                discovery.capabilities.cms_regions,
                discovery.device_status,
            );
        })
    };
    let release = agent.into_transport().close();
    match (result, release) {
        (Err(error), Err(release)) => {
            Err(error.context(format!("interface cleanup also failed: {release:#}")))
        }
        (Err(error), _) => Err(error),
        (Ok(()), release) => release,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_explicit_identity_and_valid_timeouts() {
        assert!(Args::try_parse_from(["agent", "probe"]).is_err());
        assert!(
            Args::try_parse_from(["agent", "--vid", "0xffff", "--pid", "0xffff", "probe"]).is_ok()
        );
        assert!(Args::try_parse_from([
            "agent",
            "--vid",
            "1",
            "--pid",
            "2",
            "--transfer-timeout-ms",
            "0",
            "probe"
        ])
        .is_err());
        assert!(Args::try_parse_from(["agent", "--vid", "1", "--pid", "2", "recover"]).is_err());
    }
}
