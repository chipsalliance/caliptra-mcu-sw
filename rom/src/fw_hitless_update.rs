/*++

Licensed under the Apache-2.0 license.

File Name:

    cold_boot.rs

Abstract:

    Cold Boot Flow - Handles initial boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

#[cfg(any(
    not(feature = "test-force-hitless-update"),
    all(target_arch = "riscv32", feature = "fw-manifest-dot")
))]
use crate::fatal_error;
#[cfg(target_arch = "riscv32")]
use crate::MCU_MEMORY_MAP;
use crate::{BootFlow, RomEnv, RomParameters};
#[cfg(not(feature = "test-force-hitless-update"))]
use caliptra_api::{mailbox::MailboxRespHeader, CaliptraApiError};
use core::fmt::Write;
#[cfg(not(feature = "test-force-hitless-update"))]
use mcu_error::McuError;
#[cfg(any(
    all(target_arch = "riscv32", feature = "fw-manifest-dot"),
    not(feature = "test-force-hitless-update")
))]
use romtime::HexWord;
#[cfg(target_arch = "riscv32")]
use romtime::McuBootMilestones;
#[cfg(all(target_arch = "riscv32", feature = "fw-manifest-dot"))]
use romtime::McuRomBootStatus;
#[cfg(all(target_arch = "riscv32", feature = "fw-manifest-dot"))]
use zerocopy::FromBytes;

#[cfg(all(target_arch = "riscv32", feature = "fw-manifest-dot"))]
use crate::device_ownership_transfer;

pub struct FwHitlessUpdate {}

impl BootFlow for FwHitlessUpdate {
    fn run(env: &mut RomEnv, _params: RomParameters) -> ! {
        romtime::println!("[mcu-rom] Starting fw hitless update flow");

        // Create local references to minimize code changes
        let soc_manager = &mut env.soc_manager;
        let soc = &env.soc;

        // Release mailbox from activate command before device reboot
        #[cfg(not(feature = "test-force-hitless-update"))]
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

        #[cfg(not(feature = "test-force-hitless-update"))]
        while !soc.fw_ready() {}

        // Silence unused-variable warnings when the test feature elides the
        // mailbox release and fw-ready wait above.
        #[cfg(feature = "test-force-hitless-update")]
        {
            let _ = soc_manager;
            let _ = soc;
        }

        // Jump to firmware
        romtime::println!("[mcu-rom] Jumping to firmware");

        #[cfg(target_arch = "riscv32")]
        unsafe {
            #[cfg_attr(not(feature = "fw-manifest-dot"), allow(unused_mut))]
            let mut firmware_offset = _params.mcu_image_header_size as u32;

            // Process optional firmware manifest DOT section, mirroring the
            // cold-boot FwBoot path so that a hitless update carrying a new
            // DOT header applies its commands on this boot rather than
            // deferring them to the next cold reset.
            #[cfg(feature = "fw-manifest-dot")]
            if _params.fw_manifest_dot_enabled {
                let manifest_size =
                    core::mem::size_of::<device_ownership_transfer::FwManifestDotSection>();
                let sram = core::slice::from_raw_parts(
                    MCU_MEMORY_MAP.sram_offset as *const u8,
                    manifest_size,
                );
                if let Ok((section, _)) =
                    device_ownership_transfer::FwManifestDotSection::ref_from_prefix(sram)
                {
                    if section.magic == device_ownership_transfer::FW_MANIFEST_DOT_MAGIC {
                        firmware_offset += manifest_size as u32;

                        env.mci.set_flow_checkpoint(
                            McuRomBootStatus::FwManifestDotProcessingStarted.into(),
                        );
                        if let Err(err) =
                            device_ownership_transfer::process_fw_manifest_dot_commands(
                                env,
                                section,
                                _params.dot_flash,
                            )
                        {
                            romtime::println!(
                                "[mcu-rom] Error in firmware manifest DOT: {}",
                                HexWord(err.into())
                            );
                            fatal_error(err);
                        }
                        env.mci.set_flow_checkpoint(
                            McuRomBootStatus::FwManifestDotProcessingComplete.into(),
                        );
                    }
                }
            }

            env.mci
                .set_flow_milestone(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE.into());

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
