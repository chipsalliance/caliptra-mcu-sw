/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_boot.rs

Abstract:

    Warm Boot Flow - Handles warm boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

use romtime::McuError;

use crate::{
    fatal_error, BootFlow, McuBootMilestones, McuRomBootStatus, RomEnv, RomParameters,
    MCU_MEMORY_MAP,
};
use core::fmt::Write;

pub struct WarmBoot {}

impl BootFlow for WarmBoot {
    fn run(env: &mut RomEnv, params: RomParameters) -> ! {
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::WarmResetFlowStarted.into());
        romtime::println!("[mcu-rom] Starting warm boot flow");

        // Create local references to minimize code changes
        let mci = &env.mci;
        let soc = &env.soc;

        romtime::println!("[mcu-rom] Setting Caliptra boot go");
        mci.caliptra_boot_go();
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraBootGoAsserted.into());
        mci.set_flow_milestone(McuBootMilestones::CPTRA_BOOT_GO_ASSERTED.into());

        romtime::println!(
            "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
            soc.ready_for_fuses()
        );
        while !soc.ready_for_fuses() {}
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraReadyForFuses.into());

        // According to https://github.com/chipsalliance/caliptra-rtl/blob/main/docs/CaliptraIntegrationSpecification.md#fuses
        // we still need to write the fuse write done bit even though fuses can't be changed on a
        // warm reset.

        romtime::println!("[mcu-rom] Setting Caliptra fuse write done");
        soc.fuse_write_done();
        while soc.ready_for_fuses() {}
        mci.set_flow_checkpoint(McuRomBootStatus::FuseWriteComplete.into());
        mci.set_flow_milestone(McuBootMilestones::CPTRA_FUSES_WRITTEN.into());

        romtime::println!("[mcu-rom] Waiting for MCU firmware to be ready");
        soc.wait_for_firmware_ready(mci);
        romtime::println!("[mcu-rom] Firmware is ready");

        // Check that the firmware was actually loaded before jumping to it
        let firmware_ptr = unsafe {
            (MCU_MEMORY_MAP.sram_offset + params.mcu_image_header_size as u32) as *const u32
        };
        // Safety: this address is valid
        if unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {
            romtime::println!("Invalid firmware detected; halting");
            fatal_error(McuError::WARM_BOOT_INVALID_FIRMWARE);
        }

        // Reset so FirmwareBootReset can jump to firmware
        romtime::println!("[mcu-rom] Resetting to boot firmware");
        mci.set_flow_checkpoint(McuRomBootStatus::WarmResetFlowComplete.into());
        mci.set_flow_milestone(McuBootMilestones::WARM_RESET_FLOW_COMPLETE.into());
        mci.trigger_warm_reset();
        romtime::println!("[mcu-rom] ERROR: Still running after reset request!");
        fatal_error(McuError::WARM_BOOT_RESET_ERROR);
    }
}
