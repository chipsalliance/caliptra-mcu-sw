// Licensed under the Apache-2.0 license
//
// A simple bare metal runtime that prints to the emulator UART.

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
use core::arch::global_asm;

#[cfg(target_arch = "riscv32")]
use core::panic::PanicInfo;

#[cfg(target_arch = "riscv32")]
global_asm!(include_str!("start.S"));

#[cfg(target_arch = "riscv32")]
const MSG: &[u8; 31] = b"Hello from Bare Metal Runtime!\n";

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub extern "C" fn main() {
    // Write the message to the console.
    const UART0: *mut u8 = 0x1000_1041 as *mut u8;
    unsafe {
        for byte in MSG {
            core::ptr::write_volatile(UART0, *byte);
        }
        core::ptr::write_volatile(UART0, b'\n');
    }
    // Exit the emulator.
    unsafe {
        core::ptr::write_volatile(0x1000_2000 as *mut u32, 0);
    }
}

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// Dummy main for non-RISC-V targets.
#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {}
