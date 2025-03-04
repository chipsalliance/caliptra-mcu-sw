// Licensed under the Apache-2.0 license

use crate::Commands;
use crate::{
    rom::rom_build, runtime_build::runtime_build_with_apps, DynError, PROJECT_ROOT, TARGET,
};
use std::process::Command as StdCommand;

/// Run the Runtime Tock kernel image for RISC-V in the emulator.
pub(crate) fn runtime_run(args: Commands) -> Result<(), DynError> {
    let Commands::Runtime {
        trace,
        i3c_port,
        features,
        no_stdin,
        caliptra_rom,
        caliptra_firmware,
        soc_manifest,
        active_mode,
        vendor_pk_hash,
        owner_pk_hash,
    } = args
    else {
        panic!("Must call runtime_run with Commands::Runtime");
    };
    let features: Vec<&str> = features.iter().map(|x| x.as_str()).collect();
    rom_build()?;
    runtime_build_with_apps(&features, None)?;
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
    if let Some(caliptra_rom) = caliptra_rom.as_ref() {
        if !caliptra_rom.exists() {
            return Err(format!("Caliptra ROM file not found: {:?}", caliptra_rom).into());
        }
        cargo_run_args.extend([
            "--caliptra",
            "--caliptra-rom",
            caliptra_rom.to_str().unwrap(),
        ]);
    }
    if let Some(caliptra_firmware) = caliptra_firmware.as_ref() {
        if !caliptra_firmware.exists() {
            return Err(
                format!("Caliptra runtime bundle not found: {:?}", caliptra_firmware).into(),
            );
        }
        cargo_run_args.extend(["--caliptra-firmware", caliptra_firmware.to_str().unwrap()]);
    }
    if let Some(soc_manifest) = soc_manifest.as_ref() {
        cargo_run_args.extend(["--soc-manifest", soc_manifest.to_str().unwrap()]);
    }
    if active_mode {
        cargo_run_args.extend(["--active-mode"]);
    }
    if let Some(vendor_pk_hash) = vendor_pk_hash.as_ref() {
        cargo_run_args.extend(["--vendor-pk-hash", vendor_pk_hash]);
    }
    if let Some(owner_pk_hash) = owner_pk_hash.as_ref() {
        cargo_run_args.extend(["--owner-pk-hash", owner_pk_hash]);
    }
    StdCommand::new("cargo")
        .args(cargo_run_args)
        .current_dir(&*PROJECT_ROOT)
        .status()?;
    Ok(())
}
