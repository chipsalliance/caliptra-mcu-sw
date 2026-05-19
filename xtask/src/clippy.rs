// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use caliptra_mcu_builder::features::RomVariant;
use caliptra_mcu_builder::PROJECT_ROOT;
use std::process::Command;

pub(crate) fn clippy(_rom_variants: &[RomVariant]) -> Result<()> {
    clippy_all()?;
    // TODO: extend coverage with `clippy_rom_variants(_rom_variants)`
    // once each ROM variant is clippy-clean.
    // Tracked in https://github.com/chipsalliance/caliptra-mcu-sw/issues/1478
    Ok(())
}

/// Public entry point for `cargo xtask clippy-rom-variants`, the
/// on-demand per-variant pass. Lets users (and the TODO follow-up
/// PR) exercise per-variant clippy without rewiring `precheckin`.
pub(crate) fn rom_variants(variants: &[RomVariant]) -> Result<()> {
    clippy_rom_variants(variants)
}

fn clippy_all() -> Result<()> {
    println!("Running: cargo clippy --workspace");
    let mut args = vec!["clippy", "--workspace"];
    args.extend(["--", "-D", "warnings", "--no-deps"]);
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(args)
        .env("RUSTFLAGS", "-Cpanic=abort")
        .status()?;

    if !status.success() {
        bail!("cargo clippy --workspace failed");
    }
    Ok(())
}

/// Run clippy against every ROM variant so feature-gated code paths
/// in `mcu-rom-{emulator,fpga}` are linted with their actual feature
/// set (the workspace clippy pass only exercises default features).
///
/// Attempts every variant before bailing, so a single noisy variant
/// doesn't mask the others.
fn clippy_rom_variants(variants: &[RomVariant]) -> Result<()> {
    let mut failed: Vec<String> = Vec::new();
    for variant in variants {
        let display = variant.display();
        let platform = variant.platform.unwrap_or("emulator");
        let package = format!("mcu-rom-{platform}");
        println!("Running: cargo clippy --package {package} for {display}");
        let mut args = vec![
            "clippy".to_string(),
            "--package".to_string(),
            package.clone(),
            "--target".to_string(),
            "riscv32imc-unknown-none-elf".to_string(),
            "--release".to_string(),
        ];
        if let Some(features) = variant.features {
            if !features.is_empty() {
                args.push("--features".to_string());
                args.push(features.to_string());
            }
        }
        args.extend(["--".to_string(), "-D".to_string(), "warnings".to_string()]);

        let status = Command::new("cargo")
            .current_dir(&*PROJECT_ROOT)
            .args(&args)
            .status()?;

        if !status.success() {
            failed.push(display);
        }
    }
    if !failed.is_empty() {
        bail!(
            "cargo clippy failed for {} ROM variant(s):\n  - {}",
            failed.len(),
            failed.join("\n  - ")
        );
    }
    Ok(())
}
