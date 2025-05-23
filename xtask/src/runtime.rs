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
        manufacturing_mode,
        vendor_pk_hash,
        streaming_boot,
        soc_images,
        flash_image,
    } = args
    else {
        panic!("Must call runtime_run with Commands::Runtime");
    };

    let features: Vec<&str> = features.iter().map(|x| x.as_str()).collect();
    rom_build()?;
    runtime_build_with_apps(&features, None, false)?;
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
        soc_images,
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
    // map the memory map to the emulator
    let rom_offset = format!(
        "0x{:x}",
        mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_offset
    );
    cargo_run_args.extend(["--rom-offset", &rom_offset]);
    let rom_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_size);
    cargo_run_args.extend(["--rom-size", &rom_size]);
    let dccm_offset = format!(
        "0x{:x}",
        mcu_config_emulator::EMULATOR_MEMORY_MAP.dccm_offset
    );
    cargo_run_args.extend(["--dccm-offset", &dccm_offset]);
    let dccm_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.dccm_size);
    cargo_run_args.extend(["--dccm-size", &dccm_size]);
    let sram_offset = format!(
        "0x{:x}",
        mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_offset
    );
    cargo_run_args.extend(["--sram-offset", &sram_offset]);
    let sram_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_size);
    cargo_run_args.extend(["--sram-size", &sram_size]);
    let pic_offset = format!(
        "0x{:x}",
        mcu_config_emulator::EMULATOR_MEMORY_MAP.pic_offset
    );
    cargo_run_args.extend(["--pic-offset", &pic_offset]);
    let i3c_offset = format!(
        "0x{:x}",
        mcu_config_emulator::EMULATOR_MEMORY_MAP.i3c_offset
    );
    cargo_run_args.extend(["--i3c-offset", &i3c_offset]);
    let i3c_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.i3c_size);
    cargo_run_args.extend(["--i3c-size", &i3c_size]);
    let mci_offset = format!(
        "0x{:x}",
        mcu_config_emulator::EMULATOR_MEMORY_MAP.mci_offset
    );
    cargo_run_args.extend(["--mci-offset", &mci_offset]);
    let mci_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.mci_size);
    cargo_run_args.extend(["--mci-size", &mci_size]);
    let mbox_offset = format!(
        "0x{:x}",
        mcu_config_emulator::EMULATOR_MEMORY_MAP.mbox_offset
    );
    cargo_run_args.extend(["--mbox-offset", &mbox_offset]);
    let mbox_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.mbox_size);
    cargo_run_args.extend(["--mbox-size", &mbox_size]);
    let soc_offset = format!(
        "0x{:x}",
        mcu_config_emulator::EMULATOR_MEMORY_MAP.soc_offset
    );
    cargo_run_args.extend(["--soc-offset", &soc_offset]);
    let soc_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.soc_size);
    cargo_run_args.extend(["--soc-size", &soc_size]);
    let otp_offset = format!(
        "0x{:x}",
        mcu_config_emulator::EMULATOR_MEMORY_MAP.otp_offset
    );
    cargo_run_args.extend(["--otp-offset", &otp_offset]);
    let otp_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.otp_size);
    cargo_run_args.extend(["--otp-size", &otp_size]);
    let lc_offset = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.lc_offset);
    cargo_run_args.extend(["--lc-offset", &lc_offset]);
    let lc_size = format!("0x{:x}", mcu_config_emulator::EMULATOR_MEMORY_MAP.lc_size);
    cargo_run_args.extend(["--lc-size", &lc_size]);

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
    if manufacturing_mode {
        cargo_run_args.extend(["--manufacturing-mode"]);
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
    if flash_image.as_ref().is_some() {
        cargo_run_args.extend([
            "--flash-image",
            flash_image.as_ref().unwrap().to_str().unwrap(),
        ]);
    }
    Command::new("cargo")
        .args(cargo_run_args)
        .current_dir(&*PROJECT_ROOT)
        .status()?;
    Ok(())
}
