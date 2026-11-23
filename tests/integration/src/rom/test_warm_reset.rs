// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_mcu_hw_model::McuHwModel;
use caliptra_mcu_romtime::McuBootMilestones;

// TODO(zhalvorsen): Enable this test for emulator when it is supported
#[cfg_attr(not(feature = "fpga_realtime"), ignore)]
#[test]
fn test_warm_reset_success() -> Result<()> {
    // Use the shared complete-boot setup. Supplying only a flash image without
    // selecting flash boot leaves FPGA recovery disabled and returns before
    // cold boot has completed.
    let mut hw = crate::test::start_runtime_hw_model(Default::default());

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
