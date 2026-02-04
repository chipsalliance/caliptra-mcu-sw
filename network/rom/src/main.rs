/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Network Coprocessor ROM.
    This is a simple "Hello World" test program.

--*/

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
use core::panic::PanicInfo;

#[cfg(target_arch = "riscv32")]
use core::arch::global_asm;

use network_config::DEFAULT_NETWORK_MEMORY_MAP;

// Include the startup assembly code
#[cfg(target_arch = "riscv32")]
global_asm!(include_str!("start.s"));

/// UART TX data register address for Network Coprocessor
/// This is UART offset + TX register offset (0x41)
const UART_TX_ADDR: u32 = DEFAULT_NETWORK_MEMORY_MAP.uart_offset + 0x41;

/// Emulator control register for exit
const EMU_CTRL_EXIT: u32 = DEFAULT_NETWORK_MEMORY_MAP.ctrl_offset;

/// Print a single character to the UART
#[inline(never)]
fn print_char(c: u8) {
    unsafe {
        core::ptr::write_volatile(UART_TX_ADDR as *mut u8, c);
    }
}

/// Print a string to the UART
fn print_str(s: &str) {
    for b in s.bytes() {
        print_char(b);
    }
}

/// Exit the emulator with the given code
fn exit_emulator(code: u32) -> ! {
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

/// Main entry point called from assembly startup code
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub extern "C" fn main() -> ! {
    // Print hello world message
    print_str("\n");
    print_str("=====================================\n");
    print_str("  Network Coprocessor ROM Started!  \n");
    print_str("=====================================\n");

    loop {
        // Use wfi to avoid wasting CPU cycles
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// Exception handler - called when CPU encounters an exception
#[no_mangle]
pub extern "C" fn exception_handler() {
    print_str("EXCEPTION: Network ROM encountered an error!\n");
    exit_emulator(0x01);
}

/// Panic handler for no_std environment
#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    print_str("PANIC: Network ROM panicked!\n");
    exit_emulator(0x01);
}

// Dummy main for non-RISC-V targets (for cargo check on host)
#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {
    println!("Network ROM (host build - no-op)");
}
