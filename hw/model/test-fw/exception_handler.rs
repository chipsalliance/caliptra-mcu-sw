// Licensed under the Apache-2.0 license

//! A simple test rom which encounters an exception.

#![no_main]
#![no_std]

#[allow(unused)]
use mcu_rom_common;
use mcu_test_harness;

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    unsafe { core::arch::asm!("unimp") };
}
