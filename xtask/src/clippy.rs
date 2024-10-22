// Licensed under the Apache-2.0 license

use std::process::Command;

use crate::{DynError, PROJECT_ROOT};

pub(crate) fn clippy() -> Result<(), DynError> {
    clippy_all()?;
    Ok(())
}

fn clippy_all() -> Result<(), DynError> {
    println!("Running: cargo clippy");
    let mut args = vec!["clippy", "--workspace"];
    args.extend(["--", "-D", "warnings", "--no-deps"]);
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(args)
        .env("RUSTFLAGS", "-Cpanic=abort -Zpanic_abort_tests")
        .env("LIBTOCK_LINKER_FLASH", "0x20000")
        .env("LIBTOCK_LINKER_FLASH_LENGTH", "128K")
        .env("LIBTOCK_LINKER_RAM", "0x50000000")
        .env("LIBTOCK_LINKER_RAM_LENGTH", "192K")
        .status()?;

    if !status.success() {
        Err("cargo clippy failed")?;
    }
    Ok(())
}
