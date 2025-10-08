// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_hw_model::BootParams;
use caliptra_image_types::FwVerificationPqcKeyType;
use mcu_hw_model::McuHwModel;
use mcu_hw_model::{new, Fuses, InitParams};
use mcu_rom_common::McuBootMilestones;

// TODO(zhalvorsen): Enable this test for emulator when it is supported
#[cfg_attr(not(feature = "fpga_realtime"), ignore)]
#[test]
fn test_warm_reset_success() -> Result<()> {
    let binaries = mcu_builder::FirmwareBinaries::from_env()?;
    let mut hw = new(
        InitParams {
            caliptra_rom: &binaries.caliptra_rom,
            mcu_rom: &binaries.mcu_rom,
            vendor_pk_hash: binaries.vendor_pk_hash(),
            active_mode: true,
            vendor_pqc_type: Some(FwVerificationPqcKeyType::LMS),
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&binaries.caliptra_fw),
            soc_manifest: Some(&binaries.soc_manifest),
            mcu_fw_image: Some(&binaries.mcu_runtime),
            fuses: Fuses {
                fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
                vendor_pk_hash: {
                    let mut vendor_pk_hash = [0u32; 12];
                    binaries
                        .vendor_pk_hash()
                        .unwrap()
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
            ..Default::default()
        },
    )?;

    assert!(hw
        .mci_boot_milestones()
        .contains(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE));

    println!("Starting warm reset flow");

    hw.warm_reset();

    println!("Waiting for warm reset flow to complete");

    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::WARM_RESET_FLOW_COMPLETE)
    });

    assert!(hw
        .mci_boot_milestones()
        .contains(McuBootMilestones::WARM_RESET_FLOW_COMPLETE));
    Ok(())
}
