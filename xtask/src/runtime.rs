// Licensed under the Apache-2.0 license

use crate::{
    rom::rom_build, runtime_build::runtime_build_with_apps, DynError, PROJECT_ROOT, TARGET,
};
use std::{path::PathBuf, process::Command as StdCommand};

/// Run the Runtime Tock kernel image for RISC-V in the emulator.
pub(crate) fn runtime_run(
    trace: bool,
    i3c_port: Option<u16>,
    features: &[&str],
    no_stdin: bool,
    caliptra_rom: Option<&PathBuf>,
    caliptra_firmware: Option<&PathBuf>,
) -> Result<(), DynError> {
    rom_build()?;
    runtime_build_with_apps(features, None)?;
    let rom_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("rom.bin");
    let tock_binary = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join("runtime.bin");
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
    ];
    if no_stdin {
        cargo_run_args.push("--no-stdin-uart");
    }
    let port = format!("{}", i3c_port.unwrap_or(0));
    if i3c_port.is_some() {
        cargo_run_args.extend(["--i3c-port", &port]);
    }
    if trace {
        cargo_run_args.extend(["-t", "-l", PROJECT_ROOT.to_str().unwrap()]);
    }
    if let Some(caliptra_rom) = caliptra_rom {
        if !caliptra_rom.exists() {
            return Err(format!("Caliptra ROM file not found: {:?}", caliptra_rom).into());
        }
        cargo_run_args.extend([
            "--caliptra",
            "--caliptra-rom",
            caliptra_rom.to_str().unwrap(),
        ]);
    }
    if let Some(caliptra_firmware) = caliptra_firmware {
        if !caliptra_firmware.exists() {
            return Err(
                format!("Caliptra runtime bundle not found: {:?}", caliptra_firmware).into(),
            );
        }
        cargo_run_args.extend(["--caliptra-firmware", caliptra_firmware.to_str().unwrap()]);
    }
    StdCommand::new("cargo")
        .args(cargo_run_args)
        .current_dir(&*PROJECT_ROOT)
        .status()?;
    Ok(())
}
