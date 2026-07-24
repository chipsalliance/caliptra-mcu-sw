// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
// allow empty loops on fatal errors
#![allow(clippy::empty_loop)]

#[cfg(feature = "fpga")]
mod fpga {
    const FPGA_UART_OUTPUT: *mut u32 = 0xa401_1014 as *mut u32;

    pub fn print(s: &str) {
        for b in s.bytes() {
            unsafe {
                core::ptr::write_volatile(FPGA_UART_OUTPUT, b as u32 | 0x100);
            }
        }
    }

    pub fn println(s: &str) {
        print(s);
        print("\n");
    }

    pub fn exit(code: u32) -> ! {
        unsafe {
            let b = if code == 0 { 0xff } else { 0x01 };
            core::ptr::write_volatile(FPGA_UART_OUTPUT, b as u32 | 0x100);
        }
        loop {}
    }
}

#[cfg(not(feature = "fpga"))]
mod emulator {
    const UART0: *mut u8 = 0x1000_1041 as *mut u8;
    const EMU_CTRL_EXIT: *mut u32 = 0x1000_2000 as *mut u32;

    pub fn print(s: &str) {
        for b in s.bytes() {
            unsafe {
                core::ptr::write_volatile(UART0, b);
            }
        }
    }

    pub fn println(s: &str) {
        print(s);
        print("\n");
    }

    pub fn exit(code: u32) -> ! {
        unsafe {
            core::ptr::write_volatile(EMU_CTRL_EXIT, code);
        }
        loop {}
    }
}

#[cfg(feature = "fpga")]
pub use fpga::{exit, print, println};
#[cfg(feature = "fpga")]
pub const OTP_OFFSET: u32 = 0xa406_0000;
#[cfg(feature = "fpga")]
pub const LC_OFFSET: u32 = 0xa404_0000;
#[cfg(feature = "fpga")]
pub const MCI_OFFSET: u32 = 0xa800_0000;

#[cfg(not(feature = "fpga"))]
pub use emulator::{exit, print, println};
#[cfg(not(feature = "fpga"))]
pub const OTP_OFFSET: u32 = 0x7000_0000;
#[cfg(not(feature = "fpga"))]
pub const LC_OFFSET: u32 = 0x7000_0400;
#[cfg(not(feature = "fpga"))]
pub const MCI_OFFSET: u32 = 0x6000_0000;
