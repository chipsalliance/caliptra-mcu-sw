/*++

Licensed under the Apache-2.0 license.

File Name:

    cold_boot.rs

Abstract:

    Cold Boot Flow - Handles initial boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

#[cfg(target_arch = "riscv32")]
use crate::MCU_MEMORY_MAP;
use crate::{BootFlow, RomEnv, RomParameters};
use caliptra_api::SocManager;
use core::fmt::Write;

pub struct FwHitlessUpdate {}

impl BootFlow for FwHitlessUpdate {
    fn run(env: &mut RomEnv, _params: RomParameters) -> ! {
        romtime::println!("[mcu-rom] Starting fw hitless update flow");

        // Create local references to minimize code changes
        let soc_manager = &mut env.soc_manager;

        // Release mailbox from activate command before device reboot
        soc_manager.soc_mbox().execute().write(|w| w.execute(false));

        // Jump to firmware
        romtime::println!("[mcu-rom] Jumping to firmware");

        #[cfg(target_arch = "riscv32")]
        unsafe {
            let firmware_entry = MCU_MEMORY_MAP.sram_offset;
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
