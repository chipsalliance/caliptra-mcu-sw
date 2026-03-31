/*++

Licensed under the Apache-2.0 license.

File Name:

    fw_boot.rs

Abstract:

    FW Boot Flow - Handles starting mutable firmware after a cold or warm reset

--*/

use crate::{fatal_error, BootFlow, RomEnv, RomParameters, MCU_MEMORY_MAP};
use core::fmt::Write;
use mcu_error::McuError;
#[cfg(feature = "fw-manifest-dot")]
use romtime::HexWord;
use romtime::{McuBootMilestones, McuRomBootStatus};
#[cfg(feature = "fw-manifest-dot")]
use zerocopy::FromBytes;

#[cfg(feature = "fw-manifest-dot")]
use crate::device_ownership_transfer;

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
            fatal_error(McuError::ROM_FW_BOOT_INVALID_FIRMWARE);
        }

        // --- Process optional firmware manifest DOT commands ---
        // Runs during FwBoot.
        //
        // Compile-gated by the fw-manifest-dot feature so ROMs that do not
        // need this feature stay panic-free and pay no code-size cost.
        // Additionally gated at runtime by fw_manifest_dot_enabled.
        #[cfg(feature = "fw-manifest-dot")]
        if params.fw_manifest_dot_enabled {
            let manifest_size =
                core::mem::size_of::<device_ownership_transfer::FwManifestDotSection>();
            let sram = unsafe {
                core::slice::from_raw_parts(MCU_MEMORY_MAP.sram_offset as *const u8, manifest_size)
            };
            if let Ok((section, _)) =
                device_ownership_transfer::FwManifestDotSection::ref_from_prefix(sram)
            {
                if section.magic == device_ownership_transfer::FW_MANIFEST_DOT_MAGIC {
                    env.mci.set_flow_checkpoint(
                        McuRomBootStatus::FwManifestDotProcessingStarted.into(),
                    );
                    if let Err(err) = device_ownership_transfer::process_fw_manifest_dot_commands(
                        env,
                        section,
                        params.dot_flash,
                    ) {
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
