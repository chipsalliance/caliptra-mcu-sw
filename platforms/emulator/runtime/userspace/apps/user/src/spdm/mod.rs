// Licensed under the Apache-2.0 license

//! User-app SPDM MCTP responder.
//!
//! Drives the spdm-lite responder over MCTP. spdm-lite currently
//! implements version/capability/algorithm negotiation, digests,
//! certificate retrieval, and SPDM large-message chunking.

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
/// Persistent CHUNK_SEND reassembly buffer. This is kept outside the
/// async task frame and outside the per-I/O scratch allocator because
/// it must live across multiple received chunk messages.
const SPDM_LITE_LARGE_MSG_SIZE: usize = 8 * 1024;

#[embassy_executor::task]
pub(crate) async fn spdm_task() {
    let mut cw = Console::<DefaultSyscalls>::writer();
    crate::console_writeln!(cw, "SPDM_TASK: Running SPDM-TASK...");

    #[repr(C, align(64))]
    struct ScratchBuf([u8; SPDM_LITE_SCRATCH_SIZE]);
    static mut SCRATCH: ScratchBuf = ScratchBuf([0u8; SPDM_LITE_SCRATCH_SIZE]);
    struct LargeMsgBuf([u8; SPDM_LITE_LARGE_MSG_SIZE]);
    static mut LARGE_MSG: LargeMsgBuf = LargeMsgBuf([0u8; SPDM_LITE_LARGE_MSG_SIZE]);
    // SAFETY: this task is the sole owner of `SCRATCH`.
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(SCRATCH.0.as_mut_ptr()) };
    // SAFETY: this task is the sole owner of `LARGE_MSG`.
    let large_msg_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(LARGE_MSG.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    let transport = alloc::boxed::Box::new(
        McuSpdmMctpTransport::new(
            mctp::driver_num::MCTP_SPDM,
            mcu_spdm_lite_transports::mctp::MCTP_MSG_TYPE_SPDM,
        )
        .expect("MCTP_SPDM driver with MCTP_MSG_TYPE_SPDM is a valid pairing"),
    );

    // SAFETY: `SCRATCH` and `LARGE_MSG` are statically allocated and
    // exclusively owned by this task; `SCRATCH` is aligned for the
    // bitmap allocator by `#[repr(align(64))]`.
    let pal = unsafe {
        McuSpdmPal::new(
            transport,
            scratch_ptr,
            SPDM_LITE_SCRATCH_SIZE,
            Some(large_msg_ptr),
            SPDM_LITE_LARGE_MSG_SIZE,
        )
    };

    let mut stack = SpdmStack::new(pal);

    crate::console_writeln!(cw, "SPDM_TASK: starting spdm-lite run loop");
    if let Err(e) = stack.run().await {
        crate::console_writeln!(cw, "SPDM_TASK: spdm-lite run loop exited: 0x{:08x}", e);
    }
}
