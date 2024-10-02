// Licensed under the Apache-2.0 license

use std::process::Command;

use crate::{DynError, PROJECT_ROOT, TARGET};

// These projects require nightly.
const NIGHTLY_PROJECTS: &[&str] = &["emulator-examples", "runtime", "pldm-app"];

pub(crate) fn clippy() -> Result<(), DynError> {
    clippy_all()?;
    for p in NIGHTLY_PROJECTS {
        clippy_project(p)?;
    }
    Ok(())
}

fn clippy_all() -> Result<(), DynError> {
    println!("Running: cargo clippy");
    let mut args = vec!["clippy", "--workspace"];
    NIGHTLY_PROJECTS.iter().for_each(|p| {
        args.push("--exclude");
        args.push(*p);
    });
    args.extend(["--", "-D", "warnings", "--no-deps"]);
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(args)
        .status()?;

    if !status.success() {
        Err("cargo clippy failed")?;
    }
    Ok(())
}

fn clippy_project(package: &str) -> Result<(), DynError> {
    println!("Running: cargo clippy {}", package);
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args([
            "+nightly",
            "clippy",
            "-p",
            package,
            "--target",
            TARGET,
            "--no-deps",
            "--",
            "-D",
            "warnings",
        ])
        .env("RUSTFLAGS", "-Cpanic=abort -Zpanic_abort_tests")
        .env("LIBTOCK_LINKER_FLASH", "0x20000")
        .env("LIBTOCK_LINKER_FLASH_LENGTH", "128K")
        .env("LIBTOCK_LINKER_RAM", "0x50000000")
        .env("LIBTOCK_LINKER_RAM_LENGTH", "192K")
        .status()?;

    if !status.success() {
        Err(format!("cargo clippy {} failed", package))?;
    }
    Ok(())
}
