// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use mcu_builder::PROJECT_ROOT;
use std::process::Command;

pub(crate) fn cargo_lock() -> Result<()> {
    println!("Checking Cargo lock");
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["tree", "--locked"])
        .env("RUSTFLAGS", "-Cpanic=abort")
        .stdout(std::process::Stdio::null())
        .status()?;

    if !status.success() {
        bail!("cargo tree --locked failed; Please include required changes to Cargo.lock in your pull request");
    }
    Ok(())
}
