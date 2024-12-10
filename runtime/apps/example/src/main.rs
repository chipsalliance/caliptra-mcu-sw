// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

#[cfg(target_arch = "riscv32")]
mod riscv;
#[cfg(target_arch = "riscv32")]
mod tock_executor;

#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {
    // no-op on x86 just to keep the build clean
}
