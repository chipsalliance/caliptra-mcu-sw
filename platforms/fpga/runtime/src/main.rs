// Licensed under the Apache-2.0 license.

// Copyright Tock Contributors 2022.
// Copyright (c) 2024 Antmicro <www.antmicro.com>

//! Board file for VeeR EL2 emulation platform.

// Disable this attribute when documenting, as a workaround for
// https://github.com/rust-lang/rust/issues/62184.
//#![cfg_attr(not(doc), no_main)]

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
mod board;
#[cfg(target_arch = "riscv32")]
mod interrupts;
#[cfg(target_arch = "riscv32")]
pub mod io;

#[cfg(target_arch = "riscv32")]
pub use board::*;

#[cfg(target_arch = "riscv32")]
mod tests;

use mcu_config::McuMemoryMap;

// re-export this so the common runtime code can use it
#[no_mangle]
#[used]
pub static MCU_MEMORY_MAP: McuMemoryMap = mcu_config_fpga::FPGA_MEMORY_MAP;

// Define the timer frequency for the FPGA.
#[no_mangle]
#[used]
pub static TIMER_FREQUENCY_HZ: u32 = 20_000_000;

#[cfg(target_arch = "riscv32")]
#[no_mangle]
/// # Safety
///
/// Initializing the board is inherently unsafe.
pub unsafe fn main() {
    board::main();
}

#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {
    // no-op on x86 just to keep the build clean
}
