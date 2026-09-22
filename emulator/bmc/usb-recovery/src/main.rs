// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use caliptra_mcu_usb_recovery::{
    LibusbTransport, RecoveryAgent, RecoveryImages, DEFAULT_PRODUCT_ID, DEFAULT_VENDOR_ID,
};
use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    caliptra_fmc_rt: PathBuf,
    #[arg(long)]
    soc_manifest: PathBuf,
    #[arg(long)]
    mcu_runtime: PathBuf,
    #[arg(long, default_value_t = DEFAULT_VENDOR_ID)]
    vendor_id: u16,
    #[arg(long, default_value_t = DEFAULT_PRODUCT_ID)]
    product_id: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let caliptra_fmc_rt = std::fs::read(&args.caliptra_fmc_rt)
        .with_context(|| format!("failed to read {}", args.caliptra_fmc_rt.display()))?;
    let soc_manifest = std::fs::read(&args.soc_manifest)
        .with_context(|| format!("failed to read {}", args.soc_manifest.display()))?;
    let mcu_runtime = std::fs::read(&args.mcu_runtime)
        .with_context(|| format!("failed to read {}", args.mcu_runtime.display()))?;
    let images = RecoveryImages {
        caliptra_fmc_rt: &caliptra_fmc_rt,
        soc_manifest: &soc_manifest,
        mcu_runtime: &mcu_runtime,
    };
    let transport =
        LibusbTransport::open(args.vendor_id, args.product_id, Duration::from_secs(10))?;
    RecoveryAgent::new(transport).run(&images)
}
