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
use crate::{fatal_error, BootFlow, RomEnv, RomParameters};
use caliptra_api::{mailbox::MailboxRespHeader, CaliptraApiError};
use core::fmt::Write;
use mcu_error::McuError;
use romtime::HexWord;

pub struct FwHitlessUpdate {}

impl BootFlow for FwHitlessUpdate {
    fn run(env: &mut RomEnv, _params: RomParameters) -> ! {
        romtime::println!("[mcu-rom] Starting fw hitless update flow");

        // Create local references to minimize code changes
        let soc_manager = &mut env.soc_manager;
        let soc = &env.soc;

        // Release mailbox from activate command before device reboot
        if let Err(err) = soc_manager.finish_mailbox_resp(
            core::mem::size_of::<MailboxRespHeader>(),
            core::mem::size_of::<MailboxRespHeader>(),
        ) {
            match err {
                CaliptraApiError::MailboxCmdFailed(code) => {
                    romtime::println!(
                        "[mcu-rom] Error finishing mailbox command: {}",
                        HexWord(code)
                    );
                }
                _ => {
                    romtime::println!("[mcu-rom] Error finishing mailbox command");
                }
            }
            fatal_error(McuError::ROM_FW_HITLESS_UPDATE_CLEAR_MB_ERROR);
        };

        while !soc.fw_ready() {}

        // Jump to firmware
        romtime::println!("[mcu-rom] Jumping to firmware");

        #[cfg(target_arch = "riscv32")]
        unsafe {
            let firmware_entry = MCU_MEMORY_MAP.sram_offset + _params.mcu_image_header_size as u32;
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
