// Licensed under the Apache-2.0 license

use anyhow::Result;
use mcu_builder::{PROJECT_ROOT, TARGET};
use std::process::Command;

pub(crate) fn rom_run(trace: bool) -> Result<()> {
    let platform = None;
    let platform_bin = format!("mcu-rom-{}.bin", "emulator");
    mcu_builder::rom_build(platform, "")?;
    let rom_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join(&platform_bin);
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
