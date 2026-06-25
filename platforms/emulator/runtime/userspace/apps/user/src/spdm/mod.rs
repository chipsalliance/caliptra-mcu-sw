// Licensed under the Apache-2.0 license

//! User-app SPDM responder — runs spdm-lib over MCTP and DOE.
//!
//! spdm-lib implements version/capability/algorithm negotiation,
//! digests, certificate retrieval, challenge authentication, and SPDM
//! large-message chunking.

extern crate alloc;

mod caliptra_vdm;
mod cert_store;
mod device_measurements;
#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
mod pci_sig_vdm;

#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
use self::pci_sig_vdm::{emulated_ide_km::EmulatedIdeDriver, emulated_tdisp::EmulatedTdispDriver};
use caliptra_mcu_libsyscall_caliptra::doe;
use caliptra_mcu_libsyscall_caliptra::mctp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_spdm_pal::cert::store::SharedCertStore;
use caliptra_mcu_spdm_pal::{
    BitmapAllocator, McuSpdmPal, StaticBitmapAllocatorCell, BITMAP_SLOT_SIZE,
};
use caliptra_mcu_spdm_stack::SpdmStack;
use caliptra_mcu_spdm_transports::{McuSpdmDoeTransport, McuSpdmMctpTransport};
use caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::CaliptraVdm;
#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
use caliptra_mcu_spdm_vdm_handler::pci_sig::{
    ide_km::PciSigIdeKmTdispVdm,
    tdisp::{TdispResponder, TdispVersion},
};
use core::fmt::Write as _;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

/// Bitmap allocator pool size per responder task.
///
/// Must hold `MEAS_RECORD_BUF_SIZE + MeasurementProvider::SCRATCH_SIZE`
/// plus transient DPE/SHA mailbox buffers (peak ~2.4 KB during
/// certify_key for kid computation).
const SPDM_SCRATCH_SIZE: usize = 12 * 1024;

#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
const TEST_PCI_SIG_VENDOR_ID: u16 = 0x0001;
#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
const SUPPORTED_TDISP_VERSIONS: &[TdispVersion] = &[TdispVersion::V10];

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
        caliptra_mcu_spdm_pal::cert::SLOT0_LEAF_LABEL,
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
    struct ScratchBuf([u8; SPDM_SCRATCH_SIZE]);
    static mut MCTP_SCRATCH: ScratchBuf = ScratchBuf([0u8; SPDM_SCRATCH_SIZE]);
    // SAFETY: this task is the sole owner of `MCTP_SCRATCH`.
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(MCTP_SCRATCH.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    // SAFETY: `init_once` is called once per task lifetime; this is the
    // MCTP responder task. Backing memory (`MCTP_SCRATCH`) is `'static`.
    static MCTP_ALLOC_CELL: StaticBitmapAllocatorCell = StaticBitmapAllocatorCell::new();
    let allocator: &'static BitmapAllocator =
        unsafe { MCTP_ALLOC_CELL.init_once(scratch_ptr, SPDM_SCRATCH_SIZE) };

    {
        if let Err(e) = ensure_cert_store_init(allocator).await {
            crate::console_writeln!(cw, "SPDM_MCTP: cert store init failed: 0x{:08x}", e);
            return;
        }
    }

    let transport = alloc::boxed::Box::new(
        McuSpdmMctpTransport::new(
            mctp::driver_num::MCTP_SPDM,
            caliptra_mcu_spdm_transports::mctp::MCTP_MSG_TYPE_SPDM,
        )
        .expect("MCTP_SPDM driver with MCTP_MSG_TYPE_SPDM is a valid pairing"),
    );

    // SAFETY: `allocator` is the `&'static` handle obtained above and is
    // exclusive to this task.
    let pal = unsafe { McuSpdmPal::new(transport, allocator, &CERT_STORE, measurement_provider()) };
    // MCTP hosts the IANA / Caliptra VDM backend (plaintext today). DOE uses
    // the default NoVdmBackend unless the TDISP/IDE validator feature wires PCI-SIG.
    static MCTP_VDM_HOOK: caliptra_vdm::CaliptraVdmHook = caliptra_vdm::CaliptraVdmHook;
    let vdm = CaliptraVdm::new(&MCTP_VDM_HOOK);
    let mut stack = SpdmStack::<_, 1, _>::with_vdm_backend(pal, vdm);

    crate::console_writeln!(cw, "SPDM_MCTP: starting spdm-lib MCTP run loop");
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
    struct ScratchBuf([u8; SPDM_SCRATCH_SIZE]);
    static mut DOE_SCRATCH: ScratchBuf = ScratchBuf([0u8; SPDM_SCRATCH_SIZE]);
    // SAFETY: this task is the sole owner of `DOE_SCRATCH`.
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(DOE_SCRATCH.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    // SAFETY: `init_once` is called once per task lifetime; this is the
    // DOE responder task. Backing memory (`DOE_SCRATCH`) is `'static`.
    static DOE_ALLOC_CELL: StaticBitmapAllocatorCell = StaticBitmapAllocatorCell::new();
    let allocator: &'static BitmapAllocator =
        unsafe { DOE_ALLOC_CELL.init_once(scratch_ptr, SPDM_SCRATCH_SIZE) };

    {
        if let Err(e) = ensure_cert_store_init(allocator).await {
            crate::console_writeln!(cw, "SPDM_DOE: cert store init failed: 0x{:08x}", e);
            return;
        }
    }

    let transport = alloc::boxed::Box::new(doe_transport);
    // SAFETY: `allocator` is the `&'static` handle obtained above and is
    // exclusive to this task.
    let pal = unsafe { McuSpdmPal::new(transport, allocator, &CERT_STORE, measurement_provider()) };
    #[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
    let mut stack = SpdmStack::<_, 1, _>::with_vdm_backend(
        pal,
        PciSigIdeKmTdispVdm::new(
            TEST_PCI_SIG_VENDOR_ID,
            EmulatedIdeDriver::default(),
            TdispResponder::new(SUPPORTED_TDISP_VERSIONS, EmulatedTdispDriver::new())
                .expect("TDISP validator versions are non-empty"),
        ),
    );
    #[cfg(not(feature = "test-doe-spdm-tdisp-ide-validator"))]
    let mut stack: SpdmStack<_, 1> = SpdmStack::new(pal);

    crate::console_writeln!(cw, "SPDM_DOE: starting spdm-lib DOE run loop");
    if let Err(e) = stack.run().await {
        crate::console_writeln!(cw, "SPDM_DOE: DOE run loop exited: 0x{:08x}", e);
    }
}
