// Licensed under the Apache-2.0 license

//! A simple test rom which encounters an exception.

#![no_main]
#![no_std]

extern crate mcu_rom_common;

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    #[cfg(target_arch = "riscv32")]
    {
        unsafe { core::arch::asm!("unimp") };
    }
}
