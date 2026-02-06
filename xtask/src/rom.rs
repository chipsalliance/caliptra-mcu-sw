// Licensed under the Apache-2.0 license

use anyhow::Result;
use mcu_builder::PROJECT_ROOT;
use std::process::Command;

pub(crate) fn rom_run(trace: bool) -> Result<()> {
    let platform = None;
    let rom_binary = mcu_builder::rom_build(platform, None)?;
    let mut cargo_run_args = vec![
        "run",
        "-p",
        "emulator",
        "--profile",
        "test",
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
