// Licensed under the Apache-2.0 license

//! User-app SPDM responder — runs spdm-lite over MCTP and DOE.
//!
//! spdm-lite implements version/capability/algorithm negotiation,
//! digests, certificate retrieval, challenge authentication, and SPDM
//! large-message chunking.

extern crate alloc;

mod cert_store;
mod device_measurements;

use crate::caliptra_cmd_handler::CaliptraOcpVdm;
use caliptra_mcu_libsyscall_caliptra::doe;
use caliptra_mcu_libsyscall_caliptra::mctp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use core::fmt::Write as _;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use mcu_spdm_lite_pal::cert::store::SharedCertStore;
use mcu_spdm_lite_pal::{McuSpdmPal, BITMAP_SLOT_SIZE};
use mcu_spdm_lite_stack::SpdmStack;
use mcu_spdm_lite_transports::{McuSpdmDoeTransport, McuSpdmMctpTransport};

/// Bitmap allocator pool size per responder task.
///
/// Must hold `MEAS_RECORD_BUF_SIZE + MeasurementProvider::SCRATCH_SIZE`
/// (1,024 + 3,072 = 4,096) plus transient DPE/SHA mailbox buffers
/// (peak ~2.4 KB during certify_key for kid computation).
const SPDM_LITE_SCRATCH_SIZE: usize = 8 * 1024;
/// Persistent large-message buffer. This is kept outside the async task frame
/// and outside the per-I/O scratch allocator because CHUNK_SEND reassembly and
/// buffered large responses must live across multiple received chunk messages.
/// The current VDM large-response path buffers the full CSR response before
/// CHUNK_GET serves it, so this must cover the largest expected CSR response.
const SPDM_LITE_LARGE_MSG_SIZE: usize = 13 * 1024;

/// Single cert store shared by all SPDM responder tasks.
static CERT_STORE: SharedCertStore = SharedCertStore::new();

/// Signal fired when cert store init completes.
static CERT_STORE_DONE: Signal<CriticalSectionRawMutex, bool> = Signal::new();

/// Cert store init state: 0 = uninit, 1 = in progress, 2 = done.
static CERT_STORE_STATE: AtomicU8 = AtomicU8::new(0);

#[cfg(feature = "test-mctp-spdm-attestation-pcr-quote")]
fn measurement_provider() -> device_measurements::pcr_quote::PcrQuoteMeasurementProvider {
    device_measurements::pcr_quote::PcrQuoteMeasurementProvider::new()
}

#[cfg(not(feature = "test-mctp-spdm-attestation-pcr-quote"))]
fn measurement_provider() -> device_measurements::ocp_eat::OcpEatMeasurementProvider {
    device_measurements::ocp_eat::OcpEatMeasurementProvider::new(
        mcu_spdm_lite_pal::cert::SLOT0_LEAF_LABEL,
    )
}

/// Initialize the shared cert store. First caller does the work;
/// concurrent callers wait on a Signal (no busy-loop).
async fn ensure_cert_store_init<A: mcu_caliptra_api_lite::ApiAlloc>(
    alloc: &A,
) -> mcu_error::McuResult<()> {
    // Single-core cooperative executor: no preemption between load and
    // store, so load+store is equivalent to compare_exchange here.
    // (riscv32imc lacks hardware CAS.)
    let state = CERT_STORE_STATE.load(Ordering::Acquire);
    match state {
        0 => {
            CERT_STORE_STATE.store(1, Ordering::Release);
            if let Err(e) = cert_store::populate_idev(alloc).await {
                CERT_STORE_STATE.store(0, Ordering::Release);
                CERT_STORE_DONE.signal(false);
                return Err(e);
            }
            let r = cert_store::setup_endorsements(&CERT_STORE, alloc).await;
            CERT_STORE_STATE.store(if r.is_ok() { 2 } else { 0 }, Ordering::Release);
            CERT_STORE_DONE.signal(r.is_ok());
            r
        }
        1 => {
            let ok = CERT_STORE_DONE.wait().await;
            if ok {
                Ok(())
            } else {
                Err(mcu_error::codes::INTERNAL_BUG)
            }
        }
        _ => Ok(()),
    }
}

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
    struct LargeMsgBuf([u8; SPDM_LITE_LARGE_MSG_SIZE]);
    static mut MCTP_LARGE_MSG: LargeMsgBuf = LargeMsgBuf([0u8; SPDM_LITE_LARGE_MSG_SIZE]);
    // SAFETY: this task is the sole owner of `MCTP_SCRATCH`.
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(MCTP_SCRATCH.0.as_mut_ptr()) };
    // SAFETY: this task is the sole owner of `MCTP_LARGE_MSG`.
    let large_msg: &'static mut [u8] = unsafe { &mut (*core::ptr::addr_of_mut!(MCTP_LARGE_MSG)).0 };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    {
        let init_alloc =
            unsafe { mcu_spdm_lite_pal::BitmapAllocator::new(scratch_ptr, SPDM_LITE_SCRATCH_SIZE) };
        if let Err(e) = ensure_cert_store_init(&init_alloc).await {
            crate::console_writeln!(cw, "SPDM_MCTP: cert store init failed: 0x{:08x}", e);
            return;
        }
    }

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
            &CERT_STORE,
            Some(large_msg),
            measurement_provider(),
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

    #[repr(C, align(64))]
    struct ScratchBuf([u8; SPDM_LITE_SCRATCH_SIZE]);
    static mut DOE_SCRATCH: ScratchBuf = ScratchBuf([0u8; SPDM_LITE_SCRATCH_SIZE]);
    struct LargeMsgBuf([u8; SPDM_LITE_LARGE_MSG_SIZE]);
    static mut DOE_LARGE_MSG: LargeMsgBuf = LargeMsgBuf([0u8; SPDM_LITE_LARGE_MSG_SIZE]);
    // SAFETY: this task is the sole owner of `DOE_SCRATCH`.
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(DOE_SCRATCH.0.as_mut_ptr()) };
    // SAFETY: this task is the sole owner of `DOE_LARGE_MSG`.
    let large_msg: &'static mut [u8] = unsafe { &mut (*core::ptr::addr_of_mut!(DOE_LARGE_MSG)).0 };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    {
        let init_alloc =
            unsafe { mcu_spdm_lite_pal::BitmapAllocator::new(scratch_ptr, SPDM_LITE_SCRATCH_SIZE) };
        if let Err(e) = ensure_cert_store_init(&init_alloc).await {
            crate::console_writeln!(cw, "SPDM_DOE: cert store init failed: 0x{:08x}", e);
            return;
        }
    }

    let transport = alloc::boxed::Box::new(doe_transport);
    // SAFETY: `DOE_SCRATCH` and `DOE_LARGE_MSG` are statically allocated and
    // exclusively owned by this task; `DOE_SCRATCH` is aligned for the
    // bitmap allocator by `#[repr(align(64))]`.
    let pal = unsafe {
        McuSpdmPal::new(
            transport,
            scratch_ptr,
            SPDM_LITE_SCRATCH_SIZE,
            &CERT_STORE,
            Some(large_msg),
            measurement_provider(),
        )
    };
    let mut stack = SpdmStack::with_vdm_backend(pal, CaliptraOcpVdm);

    crate::console_writeln!(cw, "SPDM_DOE: starting spdm-lite DOE run loop");
    if let Err(e) = stack.run().await {
        crate::console_writeln!(cw, "SPDM_DOE: DOE run loop exited: 0x{:08x}", e);
    }
}
