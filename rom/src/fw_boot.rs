/*++

Licensed under the Apache-2.0 license.

File Name:

    fw_boot.rs

Abstract:

    FW Boot Flow - Handles starting mutable firmware after a cold or warm reset

--*/

use crate::{
    fatal_error, BootFlow, McuBootMilestones, McuRomBootStatus, RomEnv, RomParameters,
    MCU_MEMORY_MAP,
};
use core::fmt::Write;

pub struct FwBoot {}

impl BootFlow for FwBoot {
    fn run(env: &mut RomEnv, params: RomParameters) -> ! {
        romtime::println!("[mcu-rom] Starting fw boot reset flow");
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::FirmwareBootFlowStarted.into());

        // Check that the firmware was actually loaded before jumping to it
        let firmware_ptr = unsafe {
            (MCU_MEMORY_MAP.sram_offset + params.mcu_image_header_size as u32) as *const u32
        };
        // Safety: this address is valid
        if unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {
            romtime::println!("Invalid firmware detected; halting");
            fatal_error(1);
        }

        // Jump to firmware
        romtime::println!("[mcu-rom] Jumping to firmware");
        env.mci
            .set_flow_milestone(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE.into());

        #[cfg(target_arch = "riscv32")]
        unsafe {
            let firmware_entry = MCU_MEMORY_MAP.sram_offset + params.mcu_image_header_size as u32;
            core::arch::asm!(
                "jr {0}",
                in(reg) firmware_entry,
                options(noreturn)
            );
        }

        #[cfg(not(target_arch = "riscv32"))]
        panic!("Attempting to jump to firmware on non-RISC-V platform");
    }
}
