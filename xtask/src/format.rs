// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use mcu_builder::PROJECT_ROOT;
use std::process::Command;

pub(crate) fn format() -> Result<()> {
    println!("Running: cargo fmt");
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["fmt", "--check", "--all"])
        .env("RUSTFLAGS", "-Cpanic=abort")
        .status()?;

    if !status.success() {
        bail!("cargo fmt failed");
    }
    Ok(())
}
