// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use mcu_builder::PROJECT_ROOT;
use std::process::Command;

pub(crate) fn clippy() -> Result<()> {
    clippy_all()?;
    Ok(())
}

fn clippy_all() -> Result<()> {
    println!("Running: cargo clippy");
    let mut args = vec!["clippy", "--workspace"];
    args.extend(["--", "-D", "warnings", "--no-deps"]);
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(args)
        .env("RUSTFLAGS", "-Cpanic=abort")
        .status()?;

    if !status.success() {
        bail!("cargo clippy failed");
    }
    Ok(())
}
