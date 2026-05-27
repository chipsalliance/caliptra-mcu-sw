// Licensed under the Apache-2.0 license

//! User-app SPDM responder — runs spdm-lite over MCTP and DOE.
//!
//! Drives the spdm-lite responder over MCTP and DOE. spdm-lite currently
//! implements version/capability/algorithm negotiation, digests,
//! certificate retrieval, SPDM large-message chunking, and VendorDefined
//! request dispatch.

extern crate alloc;

use crate::caliptra_cmd_handler::CaliptraOcpVdm;
use caliptra_mcu_libsyscall_caliptra::doe;
use caliptra_mcu_libsyscall_caliptra::mctp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use core::fmt::Write as _;
use core::ptr::NonNull;
use embassy_executor::Spawner;
use mcu_spdm_lite_pal::{McuSpdmPal, BITMAP_SLOT_SIZE};
use mcu_spdm_lite_stack::SpdmStack;
use mcu_spdm_lite_traits::SpdmPalTransport;
use mcu_spdm_lite_transports::{McuSpdmDoeTransport, McuSpdmMctpTransport};

/// Bitmap allocator pool size per responder task.
const SPDM_LITE_SCRATCH_SIZE: usize = 8 * 1024;
/// Persistent CHUNK_SEND reassembly buffer. This is kept outside the
/// async task frame and outside the per-I/O scratch allocator because
/// it must live across multiple received chunk messages.
const SPDM_LITE_LARGE_MSG_SIZE: usize = 16 * 1024;

/// Spawn SPDM responder tasks (MCTP + DOE) on the given executor.
pub(crate) fn spawn_spdm_tasks(spawner: &Spawner) {
    let mut cw = Console::<DefaultSyscalls>::writer();

    if spawner.spawn(spdm_mctp_responder()).is_err() {
        crate::console_writeln!(cw, "SPDM: Failed to spawn MCTP responder");
    }
    if spawner.spawn(spdm_doe_responder()).is_err() {
        crate::console_writeln!(cw, "SPDM: Failed to spawn DOE responder");
    }
}

#[embassy_executor::task]
async fn spdm_mctp_responder() {
    let mut cw = Console::<DefaultSyscalls>::writer();

    #[repr(C, align(64))]
    struct ScratchBuf([u8; SPDM_LITE_SCRATCH_SIZE]);
    struct LargeMsgBuf([u8; SPDM_LITE_LARGE_MSG_SIZE]);

    static mut MCTP_SCRATCH: ScratchBuf = ScratchBuf([0u8; SPDM_LITE_SCRATCH_SIZE]);
    static mut MCTP_LARGE_MSG: LargeMsgBuf = LargeMsgBuf([0u8; SPDM_LITE_LARGE_MSG_SIZE]);

    // SAFETY: this task is the sole owner of `MCTP_SCRATCH` and
    // `MCTP_LARGE_MSG`.
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(MCTP_SCRATCH.0.as_mut_ptr()) };
    let large_msg_ptr: NonNull<u8> =
        unsafe { NonNull::new_unchecked(MCTP_LARGE_MSG.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    let transport = alloc::boxed::Box::new(
        McuSpdmMctpTransport::new(
            mctp::driver_num::MCTP_SPDM,
            mcu_spdm_lite_transports::mctp::MCTP_MSG_TYPE_SPDM,
        )
        .expect("MCTP_SPDM driver with MCTP_MSG_TYPE_SPDM is a valid pairing"),
    );

    // SAFETY: `MCTP_SCRATCH` and `MCTP_LARGE_MSG` are statically allocated and
    // exclusively owned by this task; `MCTP_SCRATCH` is aligned for the
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
    let mut stack = SpdmStack::with_vdm_backend(pal, CaliptraOcpVdm);

    crate::console_writeln!(cw, "SPDM_MCTP: starting spdm-lite MCTP run loop");
    if let Err(e) = stack.run().await {
        crate::console_writeln!(cw, "SPDM_MCTP: MCTP run loop exited: 0x{:08x}", e);
    }
}

#[embassy_executor::task]
async fn spdm_doe_responder() {
    let mut cw = Console::<DefaultSyscalls>::writer();

    let doe_transport = McuSpdmDoeTransport::new(doe::driver_num::DOE_SPDM);
    if !doe_transport.exists() {
        crate::console_writeln!(cw, "SPDM_DOE: No DOE device, exiting");
        return;
    }

    let mtu = doe_transport.mtu();
    let hdr = doe_transport.header_size();
    crate::console_writeln!(cw, "SPDM_DOE: DOE mtu={} header={}", mtu, hdr);

    #[repr(C, align(64))]
    struct ScratchBuf([u8; SPDM_LITE_SCRATCH_SIZE]);
    struct LargeMsgBuf([u8; SPDM_LITE_LARGE_MSG_SIZE]);

    static mut DOE_SCRATCH: ScratchBuf = ScratchBuf([0u8; SPDM_LITE_SCRATCH_SIZE]);
    static mut DOE_LARGE_MSG: LargeMsgBuf = LargeMsgBuf([0u8; SPDM_LITE_LARGE_MSG_SIZE]);

    // SAFETY: this task is the sole owner of `DOE_SCRATCH` and `DOE_LARGE_MSG`.
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(DOE_SCRATCH.0.as_mut_ptr()) };
    let large_msg_ptr: NonNull<u8> =
        unsafe { NonNull::new_unchecked(DOE_LARGE_MSG.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    let transport = alloc::boxed::Box::new(doe_transport);
    // SAFETY: `DOE_SCRATCH` and `DOE_LARGE_MSG` are statically allocated and
    // exclusively owned by this task; `DOE_SCRATCH` is aligned for the
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
    let mut stack = SpdmStack::with_vdm_backend(pal, CaliptraOcpVdm);

    crate::console_writeln!(cw, "SPDM_DOE: starting spdm-lite DOE run loop");
    if let Err(e) = stack.run().await {
        crate::console_writeln!(cw, "SPDM_DOE: DOE run loop exited: 0x{:08x}", e);
    }
}
