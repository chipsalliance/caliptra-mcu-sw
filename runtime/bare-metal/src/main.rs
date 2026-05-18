// Licensed under the Apache-2.0 license
//
// A simple bare metal runtime that prints to the emulator UART.

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
mod riscv {
    use core::arch::global_asm;
    use core::panic::PanicInfo;

    global_asm!(include_str!("start.S"));

    const FPGA_UART_OUTPUT: *mut u32 = 0xa401_1014 as *mut u32;
    const UART0: *mut u8 = 0x1000_1041 as *mut u8;
    const EMU_CTRL_EXIT: *mut u32 = 0x1000_2000 as *mut u32;

    const MSG: &[u8] = b"Hello from Bare Metal Runtime!\n";

    unsafe fn write_byte(byte: u8) {
        if cfg!(feature = "fpga") {
            core::ptr::write_volatile(FPGA_UART_OUTPUT, byte as u32 | 0x100);
        } else {
            core::ptr::write_volatile(UART0, byte);
        }
    }

    unsafe fn exit_runtime() -> ! {
        if cfg!(feature = "fpga") {
            // Signal exit success over UART for direct simulation runs
            core::ptr::write_volatile(FPGA_UART_OUTPUT, 0xff | 0x100);
        } else {
            core::ptr::write_volatile(EMU_CTRL_EXIT, 0);
        }
        loop {}
    }

    #[no_mangle]
    pub extern "C" fn main() {
        unsafe {
            for &byte in MSG {
                write_byte(byte);
            }
            exit_runtime();
        }
    }

    #[panic_handler]
    fn panic(_info: &PanicInfo) -> ! {
        loop {}
    }
}

// Dummy main for non-RISC-V targets.
#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {}
