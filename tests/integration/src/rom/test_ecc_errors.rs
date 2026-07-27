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
    let binaries = caliptra_mcu_builder::FirmwareBinaries::from_env().unwrap();
    let bundle = binaries.as_bundle(&caliptra_mcu_builder::firmware::targets::TEST_DO_NOTHING);
    let caliptra_rom = bundle.caliptra_rom.0.clone();
    let mcu_rom = bundle.mcu_rom.0.clone();
    let caliptra_fw = bundle.caliptra_rt.0.clone();
    let soc_manifest = bundle.soc_manifest.0.clone();
    let mcu_runtime = bundle.mcu_fw.bytes.clone();
    let vendor_pk_hash_u8 = binaries.vendor_pk_hash().unwrap().to_vec();

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
        0x5_0016,
        "[mcu-rom] Caliptra reported an ICCM ECC uncorrectable error",
    )
}

#[test]
fn test_rom_dccm_ecc_unc() -> Result<()> {
    test_rom_hw_error(
        0x2,
        0x5_0017,
        "[mcu-rom] Caliptra reported a DCCM ECC uncorrectable error",
    )
}
