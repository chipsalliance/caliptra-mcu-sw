/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for MCU ROM

--*/

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]

mod error;
#[cfg(target_arch = "riscv32")]
mod fuses;
#[cfg(target_arch = "riscv32")]
mod io;
#[cfg(target_arch = "riscv32")]
mod riscv;

mod static_ref;

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub extern "C" fn main() {
    riscv::rom_entry();
}

#[cfg(not(target_arch = "riscv32"))]
#[no_mangle]
pub extern "C" fn main() {
    // no-op on x86 just to keep the build clean
}

#[no_mangle]
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn panic_is_possible() {
    core::hint::black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}

#[panic_handler]
#[inline(never)]
#[cfg(target_arch = "riscv32")]
fn rom_panic(_: &core::panic::PanicInfo) -> ! {
    panic_is_possible();
    io::write(b"Panic!\r\n");

    fatal_error();
}

#[cfg(target_arch = "riscv32")]
#[inline(never)]
#[allow(dead_code)]
#[allow(clippy::empty_loop)]
pub(crate) fn fatal_error() -> ! {
    // Cause the emulator to exit
    unsafe {
        core::ptr::write_volatile(0x1000_2000 as *mut u32, 1);
    }
    loop {}
}

#[cfg(not(target_arch = "riscv32"))]
#[inline(never)]
#[allow(dead_code)]
#[allow(clippy::empty_loop)]
pub(crate) fn fatal_error() -> ! {
    loop {}
}
