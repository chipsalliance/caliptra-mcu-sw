/*++

Licensed under the Apache-2.0 license.

File Name:

    system.rs

Abstract:

    System utilities for Network Coprocessor.

--*/

use network_config::DEFAULT_NETWORK_MEMORY_MAP;

/// Emulator control register for exit
const EMU_CTRL_EXIT: u32 = DEFAULT_NETWORK_MEMORY_MAP.ctrl_offset;

/// Exit the emulator with the given code
///
/// This function writes to the emulator control register to signal
/// that the simulation should terminate with the given exit code.
///
/// # Arguments
/// * `code` - Exit code (0 = success, non-zero = error)
pub fn exit_emulator(code: u32) -> ! {
    unsafe {
        core::ptr::write_volatile(EMU_CTRL_EXIT as *mut u32, code);
    }
    #[allow(clippy::empty_loop)]
    loop {
        // Use wfi to avoid wasting CPU cycles on RISC-V
        #[cfg(target_arch = "riscv32")]
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}
