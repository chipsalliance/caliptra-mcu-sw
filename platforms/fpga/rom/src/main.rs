/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for MCU ROM

--*/

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
mod io;
#[cfg(target_arch = "riscv32")]
mod riscv;

#[cfg(target_arch = "riscv32")]
mod flash;

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub extern "C" fn main() {
    riscv::rom_entry();
}

#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {
    // no-op on x86 just to keep the build clean
    println!("nop");
}
