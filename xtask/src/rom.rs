// Licensed under the Apache-2.0 license

use crate::{DynError, PROJECT_ROOT, TARGET};
use std::process::Command;

pub fn rom_build() -> Result<(), DynError> {
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .env("RUSTFLAGS", "-C link-arg=-Trom/layout.ld")
        .args(["b", "-p", "rom", "--release", "--target", TARGET])
        .status()?;
    if !status.success() {
        Err("build ROM binary failed")?;
    }
    Ok(())
}

pub(crate) fn rom_run(trace: bool) -> Result<(), DynError> {
    rom_build()?;
    let rom_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("rom");
    let mut cargo_run_args = vec![
        "run",
        "-p",
        "emulator",
        "--release",
        "--",
        "--rom",
        rom_binary.to_str().unwrap(),
    ];
    if trace {
        cargo_run_args.extend(["-t", "-l", PROJECT_ROOT.to_str().unwrap()]);
    }
    Command::new("cargo")
        .args(cargo_run_args)
        .current_dir(&*PROJECT_ROOT)
        .status()?;
    Ok(())
}
