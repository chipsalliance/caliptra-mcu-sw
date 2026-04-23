// Licensed under the Apache-2.0 license

//! This file contains integration tests for the MCU ROM to verify it correctly
//! detects and handles ICCM and DCCM ECC uncorrectable errors reported by Caliptra
//! via the `cptra_hw_error_fatal` register.

use anyhow::Result;
use caliptra_api::SocManager;
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_mcu_builder::flash_image::build_flash_image_bytes;
use caliptra_mcu_hw_model::McuHwModel;
use caliptra_mcu_hw_model::{new, Fuses, InitParams};
use caliptra_mcu_romtime::McuBootMilestones;
use std::io::Write;

fn test_rom_hw_error(inject_val: u32, expected_error: u32, expected_message: &str) -> Result<()> {
    // Use the prebuilt firmware bundle if available; otherwise compile.
    let (caliptra_rom, mcu_rom, caliptra_fw, soc_manifest, mcu_runtime, vendor_pk_hash_u8) =
        if let Ok(binaries) = caliptra_mcu_builder::FirmwareBinaries::from_env() {
            (
                binaries.caliptra_rom.clone(),
                binaries.mcu_rom.clone(),
                binaries.caliptra_fw.clone(),
                binaries.soc_manifest.clone(),
                binaries.mcu_runtime.clone(),
                binaries.vendor_pk_hash().unwrap().to_vec(),
            )
        } else {
            println!("Could not find prebuilt firmware binaries, building firmware...");
            let tb = crate::test::build_test_binaries(&crate::test::TestParams::default());
            (
                tb.caliptra_rom,
                tb.mcu_rom,
                tb.caliptra_fw,
                tb.soc_manifest,
                tb.mcu_runtime,
                tb.vendor_pk_hash_u8,
            )
        };

    // Build flash image from firmware binaries
    let flash_image =
        build_flash_image_bytes(Some(&caliptra_fw), Some(&soc_manifest), Some(&mcu_runtime));

    // Instantiate the hw model.
    let mut hw = new(InitParams {
        fuses: Fuses {
            fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
            vendor_pk_hash: {
                let mut vendor_pk_hash = [0u32; 12];
                vendor_pk_hash_u8
                    .chunks(4)
                    .enumerate()
                    .for_each(|(i, chunk)| {
                        let mut array = [0u8; 4];
                        array.copy_from_slice(chunk);
                        vendor_pk_hash[i] = u32::from_be_bytes(array);
                    });
                vendor_pk_hash
            },
            ..Default::default()
        },
        caliptra_rom: &caliptra_rom,
        mcu_rom: &mcu_rom,
        vendor_pk_hash: Some(vendor_pk_hash_u8.as_slice().try_into().unwrap()),
        active_mode: true,
        vendor_pqc_type: Some(FwVerificationPqcKeyType::LMS),
        primary_flash_initial_contents: Some(flash_image),
        check_booted_to_runtime: false, // Don't wait for runtime boot to complete
        ..Default::default()
    })?;

    // Step until Caliptra fuses are written, just before waiting for mailbox ready
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::CPTRA_FUSES_WRITTEN)
    });

    // Inject the hardware error.
    println!("Injecting hardware error value: 0x{:x}", inject_val);
    hw.caliptra_soc_manager()
        .soc_ifc()
        .cptra_hw_error_fatal()
        .write(|_| inject_val.into());

    // Step until fatal error is reported in MCI
    hw.step_until(|hw| hw.mci_fw_fatal_error().is_some());
    let fatal_error = hw.mci_fw_fatal_error().unwrap();
    assert_eq!(fatal_error, expected_error);

    // Verify UART output showing the hardware error was caught by the MCU ROM.
    let mut output = Vec::new();
    output.write_all(hw.output().take(usize::MAX).as_bytes())?;
    let output_str = String::from_utf8_lossy(&output);
    assert!(output_str.contains(expected_message));

    Ok(())
}

#[test]
fn test_rom_iccm_ecc_unc() -> Result<()> {
    test_rom_hw_error(
        0x1,
        0x5_0011,
        "[mcu-rom] Caliptra reported an ICCM ECC uncorrectable error",
    )
}

#[test]
fn test_rom_dccm_ecc_unc() -> Result<()> {
    test_rom_hw_error(
        0x2,
        0x5_0012,
        "[mcu-rom] Caliptra reported a DCCM ECC uncorrectable error",
    )
}
