// Licensed under the Apache-2.0 license

use crate::platform;
use anyhow::Result;
use caliptra_mcu_builder::CaliptraBuildArgs;
use caliptra_mcu_hw_model::{new, InitParams, McuHwModel};
use caliptra_mcu_romtime::McuBootMilestones;

// TODO(zhalvorsen): Enable this test for emulator when it is supported
#[cfg_attr(not(feature = "fpga_realtime"), ignore)]
#[test]
fn test_hitless_update_flow() -> Result<()> {
    let mcu_rom_id = &caliptra_mcu_builder::firmware::hw_model_tests::HITLESS_UPDATE_FLOW;
    let cptra_rom_id = &caliptra_builder::firmware::hw_model_tests::MCU_HITLESS_UPDATE_FLOW;
    let (caliptra_rom, mcu_rom) =
        if let Ok(binaries) = caliptra_mcu_builder::FirmwareBinaries::from_env() {
            let bundle = binaries
                .as_bundle(&caliptra_mcu_builder::firmware::targets::TEST_HITLESS_UPDATE_FLOW);
            (bundle.caliptra_rom.to_vec(), bundle.mcu_rom.to_vec())
        } else {
            let rom_file = caliptra_mcu_builder::test_rom_build(&CaliptraBuildArgs {
                platform: Some(platform()),
                fwid: Some(mcu_rom_id),
                ..Default::default()
            })?;
            (
                caliptra_builder::build_firmware_rom(cptra_rom_id).unwrap(),
                std::fs::read(&rom_file)?,
            )
        };
    let mut hw = new(InitParams {
        caliptra_rom: &caliptra_rom,
        mcu_rom: &mcu_rom,
        enable_mcu_uart_log: true,
        ..Default::default()
    })?;

    println!("Waiting for flow to start");
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::CPTRA_BOOT_GO_ASSERTED)
    });

    println!("Waiting for flow to finish");
    hw.step_until(|hw| {
        hw.mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
    });

    assert!(hw
        .mci_boot_milestones()
        .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE));

    Ok(())
}
