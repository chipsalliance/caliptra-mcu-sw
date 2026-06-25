/*++

Licensed under the Apache-2.0 license.

File Name:

    fw_boot.rs

Abstract:

    FW Boot Flow - Handles starting mutable firmware after a cold or warm reset

--*/

use crate::firmware_headers::process_firmware_headers;
use crate::{fatal_error, BootFlow, RomEnv, RomParameters, MCU_MEMORY_MAP};
use caliptra_mcu_error::McuError;
use caliptra_mcu_romtime::{McuBootMilestones, McuRomBootStatus};

pub struct FwBoot {}

impl BootFlow for FwBoot {
    fn run(env: &mut RomEnv, params: RomParameters) -> ! {
        crate::call_hook(params.hooks, |h| h.pre_fw_boot());
        caliptra_mcu_romtime::println!("[mcu-rom] Starting fw boot reset flow");
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::FirmwareBootFlowStarted.into());

        // Walk past any optional headers (DOT section, MCU Component
        // SVN Manifest, ...) to find the firmware entry point.
        let firmware_offset =
            process_firmware_headers(env, &params, params.mcu_image_header_size as u32);

        // Check that the firmware was actually loaded before jumping to it
        let firmware_ptr = unsafe { (MCU_MEMORY_MAP.sram_offset + firmware_offset) as *const u32 };
        // Safety: this address is valid
        if unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {
            caliptra_mcu_romtime::println!("Invalid firmware detected; halting");
            fatal_error(McuError::ROM_FW_BOOT_INVALID_FIRMWARE);
        }

        // Jump to firmware
        caliptra_mcu_romtime::println!("[mcu-rom] Jumping to firmware");
        env.mci
            .set_flow_milestone(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE.into());
        crate::call_hook(params.hooks, |h| h.post_fw_boot());

        #[cfg(target_arch = "riscv32")]
        unsafe {
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
