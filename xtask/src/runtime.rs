// Licensed under the Apache-2.0 license

/// Run the Runtime Tock kernel image for RISC-V in the emulator.
use std::process::Command as StdCommand;

use crate::{runtime_build::runtime_build, DynError, PROJECT_ROOT, TARGET};

pub(crate) fn runtime_run(trace: bool) -> Result<(), DynError> {
    runtime_build()?;
    let tock_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("runtime");
    let mut cargo_run_args = vec![
        "+stable",
        "run",
        "-p",
        "emulator",
        "--release",
        "--",
        "--rom",
        tock_binary.to_str().unwrap(),
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
