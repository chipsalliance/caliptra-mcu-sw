// Licensed under the Apache-2.0 license

//! User-app SPDM responder — runs spdm-lite over MCTP and DOE.

extern crate alloc;

use caliptra_mcu_libsyscall_caliptra::doe;
use caliptra_mcu_libsyscall_caliptra::mctp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use core::fmt::Write as _;
use core::ptr::NonNull;
use embassy_executor::Spawner;
use mcu_spdm_lite_pal::{McuSpdmPal, BITMAP_SLOT_SIZE};
use mcu_spdm_lite_stack::SpdmStack;
use mcu_spdm_lite_transports::{McuSpdmDoeTransport, McuSpdmMctpTransport};
use mcu_spdm_lite_traits::SpdmPalTransport;

/// Bitmap allocator pool size per responder task.
const SPDM_LITE_SCRATCH_SIZE: usize = 8 * 1024;

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
    static mut MCTP_SCRATCH: ScratchBuf = ScratchBuf([0u8; SPDM_LITE_SCRATCH_SIZE]);
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(MCTP_SCRATCH.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    let transport = alloc::boxed::Box::new(
        McuSpdmMctpTransport::new(
            mctp::driver_num::MCTP_SPDM,
            mcu_spdm_lite_transports::mctp::MCTP_MSG_TYPE_SPDM,
        )
        .expect("MCTP_SPDM driver with MCTP_MSG_TYPE_SPDM is a valid pairing"),
    );

    let pal = unsafe { McuSpdmPal::new(transport, scratch_ptr, SPDM_LITE_SCRATCH_SIZE) };
    let mut stack = SpdmStack::new(pal);

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
    static mut DOE_SCRATCH: ScratchBuf = ScratchBuf([0u8; SPDM_LITE_SCRATCH_SIZE]);
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(DOE_SCRATCH.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    let transport = alloc::boxed::Box::new(doe_transport);
    let pal = unsafe { McuSpdmPal::new(transport, scratch_ptr, SPDM_LITE_SCRATCH_SIZE) };
    let mut stack = SpdmStack::new(pal);

    crate::console_writeln!(cw, "SPDM_DOE: starting spdm-lite DOE run loop");
    if let Err(e) = stack.run().await {
        crate::console_writeln!(cw, "SPDM_DOE: DOE run loop exited: 0x{:08x}", e);
    }
}
