// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_mcu_builder::{CaliptraBuilder, PROJECT_ROOT};
use std::process::Command;

pub(crate) fn rom_run(trace: bool) -> Result<()> {
    let rom_binary =
        caliptra_mcu_builder::rom_build(&caliptra_mcu_builder::CaliptraBuildArgs::default())?;

    // Use a minimal infinite-loop binary as the MCU firmware instead of
    // building the full runtime — this command is for testing the ROM only.
    let firmware_dir = PROJECT_ROOT.join("target");
    std::fs::create_dir_all(&firmware_dir)?;
    let firmware_path = firmware_dir.join("rom-stub-firmware.bin");
    // RISC-V JAL x0, 0 — jump-to-self infinite loop
    std::fs::write(&firmware_path, [0x6fu8, 0x00, 0x00, 0x00])?;

    let mut caliptra_builder = CaliptraBuilder::new(&caliptra_mcu_builder::CaliptraBuildArgs {
        mcu_firmware: Some(firmware_path.clone()),
        ..Default::default()
    });

    let caliptra_rom = caliptra_builder.get_caliptra_rom()?;
    let caliptra_firmware = caliptra_builder.get_caliptra_fw()?;
    let soc_manifest = caliptra_builder.get_soc_manifest(None)?;
    let vendor_pk_hash = caliptra_builder.get_vendor_pk_hash()?;

    let mut cargo_run_args = vec![
        "run",
        "-p",
        "caliptra-mcu-emulator",
        "--profile",
        "test",
        "--",
        "--rom",
        rom_binary.to_str().unwrap(),
        "--firmware",
        firmware_path.to_str().unwrap(),
        "--caliptra-rom",
        caliptra_rom.to_str().unwrap(),
        "--caliptra-firmware",
        caliptra_firmware.to_str().unwrap(),
        "--soc-manifest",
        soc_manifest.to_str().unwrap(),
        "--vendor-pk-hash",
        vendor_pk_hash,
    ];

    // Map the memory layout to the emulator
    let rom_offset = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_offset
    );
    cargo_run_args.extend(["--rom-offset", &rom_offset]);
    let rom_size = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.rom_size
    );
    cargo_run_args.extend(["--rom-size", &rom_size]);
    let dccm_offset = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.dccm_offset
    );
    cargo_run_args.extend(["--dccm-offset", &dccm_offset]);
    let dccm_size = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.dccm_size
    );
    cargo_run_args.extend(["--dccm-size", &dccm_size]);
    let sram_offset = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_offset
    );
    cargo_run_args.extend(["--sram-offset", &sram_offset]);
    let sram_size = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.sram_size
    );
    cargo_run_args.extend(["--sram-size", &sram_size]);
    let pic_offset = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.pic_offset
    );
    cargo_run_args.extend(["--pic-offset", &pic_offset]);
    let i3c_offset = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.i3c_offset
    );
    cargo_run_args.extend(["--i3c-offset", &i3c_offset]);
    let i3c_size = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.i3c_size
    );
    cargo_run_args.extend(["--i3c-size", &i3c_size]);
    let mci_offset = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.mci_offset
    );
    cargo_run_args.extend(["--mci-offset", &mci_offset]);
    let mci_size = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.mci_size
    );
    cargo_run_args.extend(["--mci-size", &mci_size]);
    let mbox_offset = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.mbox_offset
    );
    cargo_run_args.extend(["--mbox-offset", &mbox_offset]);
    let mbox_size = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.mbox_size
    );
    cargo_run_args.extend(["--mbox-size", &mbox_size]);
    let soc_offset = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.soc_offset
    );
    cargo_run_args.extend(["--soc-offset", &soc_offset]);
    let soc_size = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.soc_size
    );
    cargo_run_args.extend(["--soc-size", &soc_size]);
    let otp_offset = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.otp_offset
    );
    cargo_run_args.extend(["--otp-offset", &otp_offset]);
    let otp_size = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.otp_size
    );
    cargo_run_args.extend(["--otp-size", &otp_size]);
    let lc_offset = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.lc_offset
    );
    cargo_run_args.extend(["--lc-offset", &lc_offset]);
    let lc_size = format!(
        "0x{:x}",
        caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP.lc_size
    );
    cargo_run_args.extend(["--lc-size", &lc_size]);

    if trace {
        cargo_run_args.extend(["-t", "-l", PROJECT_ROOT.to_str().unwrap()]);
    }
    Command::new("cargo")
        .args(cargo_run_args)
        .current_dir(&*PROJECT_ROOT)
        .status()?;
    Ok(())
}
