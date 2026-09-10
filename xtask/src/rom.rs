// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use caliptra_mcu_builder::{CaliptraBuilder, PROJECT_ROOT};
use std::{fs::File, io::Write, process::Command};
use zerocopy::IntoBytes;

// Bytecode to write a null-terminated string to the UART, then loop forever.
// The bytecode assumes that the string immediately follows the instructions.
static ROM_STUB_INSTRUCTIONS: [u32; 10] = [
    u32::to_le(0x1000_12b7), // lui t0, 0x10001
    u32::to_le(0x0412_8293), // addi t0, t0, 0x41
    u32::to_le(0x0000_0317), // auipc t1, 0
    u32::to_le(0x0203_0313), // addi t1, t1, 32 (offset from auipc to the string)
    u32::to_le(0x0003_4383), // lbu t2, 0(t1)
    u32::to_le(0x0003_8863), // beq t2, zero, 16
    u32::to_le(0x0072_8023), // sb t2, 0(t0)
    u32::to_le(0x0013_0313), // addi t1, t1, 1
    u32::to_le(0xff1f_f06f), // jal zero, -16
    u32::to_le(0x0000_006f), // jal zero, 0
];
static ROM_STUB_START_MESSAGE: [u8; 32] = *b"[mcu-runtime] ROM stub started\n\0";

/// Build every ROM variant in the supplied list.
///
/// Used by precheckin to exercise the full ROM matrix. The linker
/// (`section '.text' will not fit in region 'ROM'`) and
/// `append_rom_digest` together fail any variant that has overflowed
/// its size budget, so a clean run of this function is sufficient
/// to confirm every variant fits.
pub(crate) fn build_all_variants(
    variants: &[caliptra_mcu_builder::features::RomVariant],
) -> Result<()> {
    for variant in variants {
        let display = variant.display();
        println!("Building ROM {display}...");
        caliptra_mcu_builder::rom_build(&caliptra_mcu_builder::CaliptraBuildArgs {
            platform: variant.platform,
            features: variant.features,
            ..Default::default()
        })
        .with_context(|| format!("building ROM variant {display}"))?;
    }
    Ok(())
}

pub(crate) fn rom_run(trace: bool) -> Result<()> {
    let rom_binary =
        caliptra_mcu_builder::rom_build(&caliptra_mcu_builder::CaliptraBuildArgs::default())?;

    // Use a minimal infinite-loop binary as the MCU firmware instead of
    // building the full runtime — this command is for testing the ROM only.
    let firmware_dir = PROJECT_ROOT.join("target");
    std::fs::create_dir_all(&firmware_dir)?;
    let firmware_path = firmware_dir.join("rom-stub-firmware.bin");
    let mut firmware = File::create(&firmware_path)?;

    // Write out the ROM stub, which prints a log string to the UART and then loops forever.
    firmware.write_all(ROM_STUB_INSTRUCTIONS.as_bytes())?;

    // Append the string to print
    firmware.write_all(&ROM_STUB_START_MESSAGE)?;

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
