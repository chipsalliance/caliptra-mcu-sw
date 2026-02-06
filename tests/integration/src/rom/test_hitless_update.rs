// Licensed under the Apache-2.0 license

use crate::platform;
use anyhow::Result;
use mcu_hw_model::{new, InitParams, McuHwModel};
use mcu_rom_common::McuBootMilestones;

// TODO(zhalvorsen): Enable this test for emulator when it is supported
#[cfg_attr(not(feature = "fpga_realtime"), ignore)]
#[test]
fn test_hitless_update_flow() -> Result<()> {
    let mcu_rom_id = &mcu_builder::firmware::hw_model_tests::HITLESS_UPDATE_FLOW;
    let cptra_rom_id = &caliptra_builder::firmware::hw_model_tests::MCU_HITLESS_UPDATE_FLOW;
    let (caliptra_rom, mcu_rom) = if let Ok(binaries) = mcu_builder::FirmwareBinaries::from_env() {
        (
            binaries.caliptra_test_rom(cptra_rom_id)?,
            binaries.test_rom(mcu_rom_id)?,
        )
    } else {
        let rom_file = mcu_builder::test_rom_build(Some(platform()), mcu_rom_id)?;
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
