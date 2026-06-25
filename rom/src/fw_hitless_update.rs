/*++

Licensed under the Apache-2.0 license.

File Name:

    cold_boot.rs

Abstract:

    Cold Boot Flow - Handles initial boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

#[cfg(not(feature = "test-force-hitless-update"))]
use crate::fatal_error;
#[cfg(target_arch = "riscv32")]
use crate::firmware_headers::process_firmware_headers;
#[cfg(target_arch = "riscv32")]
use crate::MCU_MEMORY_MAP;
use crate::{BootFlow, RomEnv, RomParameters};
#[cfg(not(feature = "test-force-hitless-update"))]
use caliptra_api::{mailbox::MailboxRespHeader, CaliptraApiError};
#[cfg(not(feature = "test-force-hitless-update"))]
use caliptra_mcu_error::McuError;

pub struct FwHitlessUpdate {}

impl BootFlow for FwHitlessUpdate {
    fn run(env: &mut RomEnv, _params: RomParameters) -> ! {
        crate::call_hook(_params.hooks, |h| h.pre_fw_hitless_update());
        caliptra_mcu_romtime::println!("[mcu-rom] Starting fw hitless update flow");

        // Create local references to minimize code changes
        let soc_manager = &mut env.soc_manager;
        let soc = &env.soc;

        // Release mailbox from activate command before device reboot.
        // Skipped under the test-force-hitless-update integration test, which
        // synthesizes the hitless reset without going through the usual
        // PLDM activate flow, so the mailbox is not in the expected state.
        #[cfg(not(feature = "test-force-hitless-update"))]
        if let Err(err) = soc_manager.finish_mailbox_resp(
            core::mem::size_of::<MailboxRespHeader>(),
            core::mem::size_of::<MailboxRespHeader>(),
        ) {
            match err {
                CaliptraApiError::MailboxCmdFailed(_) => {
                    fatal_error(McuError::ROM_FW_HITLESS_UPDATE_CLEAR_MB_CMD_FAILED);
                }
                _ => {
                    fatal_error(McuError::ROM_FW_HITLESS_UPDATE_CLEAR_MB_FAILED);
                }
            }
        };

        #[cfg(not(feature = "test-force-hitless-update"))]
        while !soc.fw_ready() {}

        #[cfg(feature = "test-force-hitless-update")]
        {
            let _ = soc_manager;
            let _ = soc;
        }

        // Jump to firmware
        caliptra_mcu_romtime::println!("[mcu-rom] Jumping to firmware");
        crate::call_hook(_params.hooks, |h| h.post_fw_hitless_update());

        #[cfg(target_arch = "riscv32")]
        unsafe {
            // Walk past any optional headers (DOT section, MCU
            // Component SVN Manifest, ...) — same as the cold-boot
            // path — so a hitless update applies any new header on
            // this boot rather than deferring it to the next reset.
            let firmware_offset =
                process_firmware_headers(env, &_params, _params.mcu_image_header_size as u32);

            env.mci.set_flow_milestone(
                caliptra_mcu_romtime::McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE.into(),
            );

            let firmware_entry = MCU_MEMORY_MAP.sram_offset + firmware_offset;
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
