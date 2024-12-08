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
mod chip;
#[cfg(target_arch = "riscv32")]
pub mod io;
#[cfg(target_arch = "riscv32")]
mod pic;
#[cfg(target_arch = "riscv32")]
#[allow(unused_imports)]
mod tests;
#[cfg(target_arch = "riscv32")]
mod timers;

#[cfg(target_arch = "riscv32")]
mod flash_ctrl;
#[cfg(target_arch = "riscv32")]
#[allow(unused_imports)]
mod flash_ctrl_test;

#[cfg(target_arch = "riscv32")]
pub use board::*;

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
