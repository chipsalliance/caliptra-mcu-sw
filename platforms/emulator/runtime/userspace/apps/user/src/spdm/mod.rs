// Licensed under the Apache-2.0 license

//! User-app SPDM MCTP responder.
//!
//! Drives the spdm-lite responder over MCTP. spdm-lite currently
//! implements GET_VERSION, GET_CAPABILITIES, and NEGOTIATE_ALGORITHMS
//! (DSP0274 §10.2–§10.4); additional commands will be added there.

extern crate alloc;

use caliptra_mcu_libsyscall_caliptra::mctp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use core::fmt::Write as _;
use core::ptr::NonNull;
use mcu_spdm_lite_pal::{McuSpdmPal, BITMAP_SLOT_SIZE};
use mcu_spdm_lite_stack::SpdmStack;
use mcu_spdm_lite_transports::McuSpdmMctpTransport;

/// Bitmap allocator pool for outbound MCTP-SPDM frames. Must be a
/// multiple of [`BITMAP_SLOT_SIZE`] (= 64 B) and large enough to hold
/// one MTU-sized response under construction.
const SPDM_LITE_SCRATCH_SIZE: usize = 8 * 1024;

#[embassy_executor::task]
pub(crate) async fn spdm_task() {
    let mut cw = Console::<DefaultSyscalls>::writer();
    crate::console_writeln!(cw, "SPDM_TASK: Running SPDM-TASK...");

    #[repr(C, align(64))]
    struct ScratchBuf([u8; SPDM_LITE_SCRATCH_SIZE]);
    static mut SCRATCH: ScratchBuf = ScratchBuf([0u8; SPDM_LITE_SCRATCH_SIZE]);
    // SAFETY: this task is the sole owner of `SCRATCH`.
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(SCRATCH.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    let transport = alloc::boxed::Box::new(
        McuSpdmMctpTransport::new(
            mctp::driver_num::MCTP_SPDM,
            mcu_spdm_lite_transports::mctp::MCTP_MSG_TYPE_SPDM,
        )
        .expect("MCTP_SPDM driver with MCTP_MSG_TYPE_SPDM is a valid pairing"),
    );

    // SAFETY: `SCRATCH` is statically allocated, exclusively owned by
    // this task, and properly aligned (see `#[repr(align(64))]`).
    let pal = unsafe { McuSpdmPal::new(transport, scratch_ptr, SPDM_LITE_SCRATCH_SIZE) };

    let mut stack = SpdmStack::new(pal);

    crate::console_writeln!(cw, "SPDM_TASK: starting spdm-lite run loop");
    if let Err(e) = stack.run().await {
        crate::console_writeln!(cw, "SPDM_TASK: spdm-lite run loop exited: 0x{:08x}", e);
    }
}
