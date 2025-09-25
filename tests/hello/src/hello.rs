/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains entry point for bare-metal RISCV program

--*/

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
use core::arch::global_asm;

#[cfg(target_arch = "riscv32")]
global_asm!(include_str!("start.S"));

#[cfg(target_arch = "riscv32")]
const OUT_STR: &[u8; 14] = b"Hello Caliptra";

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub extern "C" fn main() {
    const UART0: *mut u8 = 0x1000_1041 as *mut u8;
    unsafe {
        for byte in OUT_STR {
            core::ptr::write_volatile(UART0, *byte);
        }
        core::ptr::write_volatile(UART0, b'\n');
    }
}

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {
    println!("nop");
}
