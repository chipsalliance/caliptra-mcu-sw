// Licensed under the Apache-2.0 license

use crate::Commands;
use anyhow::Result;
use mcu_builder::{rom_build, runtime_build_with_apps, CaliptraBuilder, PROJECT_ROOT, TARGET};
use std::process::Command;

/// Run the Runtime Tock kernel image for RISC-V in the emulator.
pub(crate) fn runtime_run(args: Commands) -> Result<()> {
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
        streaming_boot,
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

    let mut caliptra_builder = CaliptraBuilder::new(
        active_mode,
        caliptra_rom,
        caliptra_firmware,
        soc_manifest,
        vendor_pk_hash,
        Some(tock_binary.clone()),
    );

    let caliptra_rom = caliptra_builder.get_caliptra_rom()?;
    let caliptra_firmware = caliptra_builder.get_caliptra_fw()?;
    let soc_manifest = caliptra_builder.get_soc_manifest()?;
    let vendor_pk_hash = caliptra_builder.get_vendor_pk_hash()?;
    let mut cargo_run_args = vec![
        "run",
        "-p",
        "emulator",
        "--release",
        "--",
        "--caliptra",
        "--rom",
        rom_binary.to_str().unwrap(),
        "--firmware",
        tock_binary.to_str().unwrap(),
        "--caliptra-rom",
        caliptra_rom.to_str().unwrap(),
        "--caliptra-firmware",
        caliptra_firmware.to_str().unwrap(),
        "--soc-manifest",
        soc_manifest.to_str().unwrap(),
        "--vendor-pk-hash",
        vendor_pk_hash,
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
    if active_mode {
        cargo_run_args.extend(["--active-mode"]);
    }
    if streaming_boot.as_ref().is_some() {
        cargo_run_args.extend([
            "--streaming-boot",
            streaming_boot.as_ref().unwrap().to_str().unwrap(),
        ]);

        // Streaming boot requires i3c port to be set
        if i3c_port.is_none() {
            cargo_run_args.extend(["--i3c-port", "65534"]);
        }
    }
    Command::new("cargo")
        .args(cargo_run_args)
        .current_dir(&*PROJECT_ROOT)
        .status()?;
    Ok(())
}
