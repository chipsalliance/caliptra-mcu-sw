// Licensed under the Apache-2.0 license

use std::process::Command;

use crate::{DynError, PROJECT_ROOT};

pub(crate) fn format() -> Result<(), DynError> {
    println!("Running: cargo fmt");
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["fmt", "--check", "--all"])
        .env("RUSTFLAGS", "-Cpanic=abort -Zpanic_abort_tests")
        .status()?;

    if !status.success() {
        Err("cargo fmt failed")?;
    }
    Ok(())
}
