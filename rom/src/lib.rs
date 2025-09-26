/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Common libraries for MCU ROM.

--*/

#![no_std]

pub mod boot_status;
pub use boot_status::*;
pub mod flash;
pub use flash::*;
mod fuses;
pub use fuses::*;
pub mod image_verifier;
pub use image_verifier::ImageVerifier;
mod rom;
pub use rom::*;
mod rom_env;
pub use rom_env::*;
mod i3c;
mod recovery;

// Boot flow modules
mod cold_boot;
mod fw_boot;
mod warm_boot;
pub use cold_boot::ColdBoot;
pub use fw_boot::FwBoot;
pub use warm_boot::WarmBoot;

mod fw_hitless_update;
pub use fw_hitless_update::FwHitlessUpdate;

pub trait FatalErrorHandler {
    fn fatal_error(&mut self, code: u32) -> !;
}

static mut FATAL_ERROR_HANDLER: Option<&'static mut dyn FatalErrorHandler> = None;

/// Set the fatal error handler.
///
/// SAFETY: it is important that the passed fatal handler is never used otherwise
/// and no other references exist to it. It is recommended to create a single instance
/// of the struct and pass it in immediatly, and never use it otherwise.
pub fn set_fatal_error_handler(handler: &'static mut dyn FatalErrorHandler) {
    unsafe {
        FATAL_ERROR_HANDLER = Some(handler);
    }
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
    fatal_error(0);
}

#[inline(never)]
#[allow(dead_code)]
#[allow(clippy::empty_loop)]
pub fn fatal_error(code: u32) -> ! {
    #[allow(static_mut_refs)]
    if let Some(handler) = unsafe { FATAL_ERROR_HANDLER.as_mut() } {
        handler.fatal_error(code);
    } else {
        // If no handler is set, just loop forever
        loop {}
    }
}
