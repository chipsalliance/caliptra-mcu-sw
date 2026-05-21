// Licensed under the Apache-2.0 license
//
// A simple bare metal runtime that prints to the emulator UART.

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
mod riscv {
    use caliptra_mcu_bare_metal_io::{exit, print};
    use core::arch::global_asm;

    global_asm!(include_str!("start.S"));

    #[no_mangle]
    pub extern "C" fn main() {
        print("Hello from Bare Metal Runtime!\n");
        exit(0);
    }

    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

// Dummy main for non-RISC-V targets.
#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {}
