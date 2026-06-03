/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Network Coprocessor ROM.

--*/

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
use core::panic::PanicInfo;

#[cfg(target_arch = "riscv32")]
use core::arch::global_asm;

use caliptra_mcu_network_drivers::{exit_emulator, println};

// Include the startup assembly code
#[cfg(target_arch = "riscv32")]
global_asm!(include_str!("start.s"));

#[cfg(target_arch = "riscv32")]
mod tests;

/// Main entry point called from assembly startup code
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub extern "C" fn main() -> ! {
    println!();
    println!("=====================================");
    println!("  Network Coprocessor ROM Started!  ");
    println!("=====================================");
    println!();

    // Run the appropriate test based on feature flags
    #[cfg(feature = "test-hello-world")]
    {
        tests::hello_world::run();
    }

    #[cfg(feature = "test-dccm")]
    {
        tests::dccm::run();
    }

    #[cfg(feature = "test-exception")]
    {
        tests::exception::run();
    }

    #[cfg(feature = "test-network-rom-dhcp-discover")]
    {
        use caliptra_mcu_network_drivers::EthernetDriver;

        // Create Ethernet driver
        let eth = EthernetDriver::new();
        caliptra_mcu_network_app_rom_test::dhcp_test::run(eth);
    }

    exit_emulator(0x00);
}

/// Exception handler - called when CPU encounters an exception
#[no_mangle]
pub extern "C" fn exception_handler() {
    #[cfg(target_arch = "riscv32")]
    {
        let mcause: u32;
        let mepc: u32;
        unsafe {
            core::arch::asm!("csrr {}, mcause", out(reg) mcause);
            core::arch::asm!("csrr {}, mepc", out(reg) mepc);
        }
        // Print "Ec=" followed by 8 hex digits of mcause, then "@" and 8 hex
        // digits of mepc. Total 19 AXI byte writes — small enough to complete
        // within the simulator's exit budget.
        #[inline(never)]
        unsafe fn putc(c: u8) {
            core::ptr::write_volatile(0x1000_1041_u32 as *mut u8, c);
        }
        #[inline(never)]
        unsafe fn puthex8(v: u32) {
            for i in (0..8).rev() {
                let nibble = ((v >> (i * 4)) & 0xF) as u8;
                putc(if nibble < 10 {
                    b'0' + nibble
                } else {
                    b'a' + nibble - 10
                });
            }
        }
        unsafe {
            putc(b'E');
            putc(b'c');
            putc(b'=');
            puthex8(mcause);
            putc(b'@');
            puthex8(mepc);
            putc(b'\r');
            putc(b'\n');
        }
    }
    exit_emulator(0x01);
}

/// Panic handler for no_std environment
#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    println!("PANIC: Network ROM panicked!");
    exit_emulator(0x01);
}

// Dummy main for non-RISC-V targets (for cargo check on host)
#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {
    println!("Network ROM (host build - no-op)");
}
