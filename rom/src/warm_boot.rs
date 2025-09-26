/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_boot.rs

Abstract:

    Warm Boot Flow - Handles warm boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

use crate::{
    fatal_error, BootFlow, McuBootMilestones, McuRomBootStatus, RomEnv, RomParameters,
    MCU_MEMORY_MAP,
};
use caliptra_api::SocManager;
use core::fmt::Write;

pub struct WarmBoot {}

impl BootFlow for WarmBoot {
    fn run(env: &mut RomEnv, params: RomParameters) -> ! {
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::WarmResetFlowStarted.into());
        romtime::println!("[mcu-rom] Starting warm boot flow");

        let soc = &env.soc;
        let mci = &env.mci;
        let soc_manager = &mut env.soc_manager;

        romtime::println!("[mcu-rom] Clearing Caliptra mailbox lock from previous session");
        soc_manager.soc_mbox().dlen().write(|_| 32);
        soc_manager.soc_mbox().execute().write(|w| w.execute(false));

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
            fatal_error(1);
        }

        // Jump to firmware
        romtime::println!("[mcu-rom] Jumping to firmware");
        mci.set_flow_milestone(McuBootMilestones::WARM_RESET_FLOW_COMPLETE.into());

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
