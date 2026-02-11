// Licensed under the Apache-2.0 license

use crate::test::{start_runtime_hw_model, TestParams};
use anyhow::Result;
use mcu_hw_model::McuHwModel;
use mcu_rom_common::McuBootMilestones;

const BOOT_CYCLES: u64 = 25_000_000;

#[test]
fn test_provision_first_hek() -> Result<()> {
    let mut hw = start_runtime_hw_model(TestParams {
        feature: Some("test-mcu-mbox-cmds"),
        ..Default::default()
    });

    assert!(hw
        .mci_boot_milestones()
        .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE));

    // This is to ensure the command happens after the mailbox responder is initialized, but it
    // doesn't change anything.
    hw.step_until(|hw| hw.cycle_count() >= BOOT_CYCLES);

    // This should get an error that says it is an unknown command, but it times out.
    let _resp = hw.mailbox_execute(0x0, &[0xaa; 8])?.unwrap();
    Ok(())
}
