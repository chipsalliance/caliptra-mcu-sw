// Licensed under the Apache-2.0 license

use crate::{
    apps_build::apps_build, rom::rom_build, runtime_build::runtime_build, DynError, PROJECT_ROOT,
    TARGET,
};
use std::process::Command as StdCommand;

/// Run the Runtime Tock kernel image for RISC-V in the emulator.
pub(crate) fn runtime_run(trace: bool) -> Result<(), DynError> {
    rom_build()?;
    runtime_build()?;
    apps_build()?;
    let rom_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("rom");
    let tock_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("runtime");
    let app_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("pldm-app");
    let mut cargo_run_args = vec![
        "run",
        "-p",
        "emulator",
        "--release",
        "--",
        "--rom",
        rom_binary.to_str().unwrap(),
        "--firmware",
        tock_binary.to_str().unwrap(),
        "--apps",
        app_binary.to_str().unwrap(),
    ];
    if trace {
        cargo_run_args.extend(["-t", "-l", PROJECT_ROOT.to_str().unwrap()]);
    }
    StdCommand::new("cargo")
        .args(cargo_run_args)
        .current_dir(&*PROJECT_ROOT)
        .status()?;
    Ok(())
}
