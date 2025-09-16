/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_boot.rs

Abstract:

    Warm Boot Flow - Handles warm boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

use crate::{fatal_error, BootFlow, RomEnv, RomParameters, MCU_MEMORY_MAP};
use caliptra_api::SocManager;
use core::fmt::Write;

pub struct WarmBoot {}

impl BootFlow for WarmBoot {
    fn run(env: &mut RomEnv, params: RomParameters) -> ! {
        romtime::println!("[mcu-rom] Starting warm boot flow");

        romtime::println!("[mcu-rom] Clearing Caliptra mailbox lock from previous session");
        env.soc_manager.soc_mbox().dlen().write(|_| 32);
        env.soc_manager
            .soc_mbox()
            .execute()
            .write(|w| w.execute(false));

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
