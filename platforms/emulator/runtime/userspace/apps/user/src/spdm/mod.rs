// Licensed under the Apache-2.0 license

//! User-app SPDM responder — runs spdm-lib over MCTP and DOE.
//!
//! spdm-lib implements version/capability/algorithm negotiation,
//! digests, certificate retrieval, challenge authentication, and SPDM
//! large-message chunking.

extern crate alloc;

mod caliptra_vdm;
mod cert_store;
#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
mod pci_sig_vdm;

#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
use self::pci_sig_vdm::{emulated_ide_km::EmulatedIdeDriver, emulated_tdisp::EmulatedTdispDriver};
#[cfg(feature = "doe")]
use caliptra_mcu_libsyscall_caliptra::doe;
use caliptra_mcu_libsyscall_caliptra::mctp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_scratch_alloc::{BitmapAllocator, StaticBitmapAllocatorCell, BITMAP_SLOT_SIZE};
use caliptra_mcu_spdm_pal::cert::store::SharedCertStore;
use caliptra_mcu_spdm_pal::McuSpdmPal;
use caliptra_mcu_spdm_stack::SpdmStack;
#[cfg(feature = "doe")]
use caliptra_mcu_spdm_transports::McuSpdmDoeTransport;
use caliptra_mcu_spdm_transports::McuSpdmMctpTransport;
#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
use caliptra_mcu_spdm_vdm_handler::pci_sig::{
    ide_km::PciSigIdeKmTdispVdm,
    tdisp::{TdispResponder, TdispVersion},
};
#[allow(unused_imports)]
use core::fmt::Write as _;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;

/// Largest single in-flight SPDM message (request or response) this responder
/// supports.
///
/// This is a contract, not a measurement: it is advertised verbatim as
/// `MaxSPDMmsgSize` in `CAPABILITIES`, so each responder scratch pool must be
/// able to satisfy it. Raising this requires raising both scratch pools; the
/// assertions below enforce that.
///
/// Sized to cover both directions, because `MaxSPDMmsgSize` caps every SPDM
/// message and the `CHUNK_SEND` admission check compares against it before the
/// streaming path is reached:
///
/// * Responses — the largest evidence this build can emit (an ML-DSA-87 PCR
///   quote is 6388 bytes) plus SPDM and vendor-defined framing.
/// * Requests — the production debug unlock token (7504 bytes of ML-DSA-87 key
///   and signature material) plus framing. This one is streamed into the
///   Caliptra mailbox and never occupies the scratch pool, but declaring a
///   smaller `MaxSPDMmsgSize` would have the responder reject it outright.
///
/// The assertions below check both against what the build actually enables, so
/// turning on a larger generator or a larger inbound command fails the build
/// rather than failing at runtime.
const MAX_SPDM_MSG_SIZE: usize = {
    let declared = 8 * 1024;
    assert!(
        declared
            >= caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::large_response_capacity::<
                crate::caliptra_cmd_handler::CaliptraCmdBackend,
            >(),
        "MaxSPDMmsgSize is smaller than the largest Caliptra VDM response this build can \
         produce; raise MAX_SPDM_MSG_SIZE (and both scratch pools with it) or disable an \
         evidence generator"
    );
    assert!(
        declared >= MAX_STREAMED_VDM_REQUEST_LEN,
        "MaxSPDMmsgSize is smaller than the largest Caliptra VDM request this build must \
         accept (the debug unlock token); raise MAX_SPDM_MSG_SIZE and both scratch pools with it"
    );
    declared
};

/// Largest streamed Caliptra VDM request this responder must accept.
///
/// The production debug unlock token dominates every other inbound request: it
/// carries an ML-DSA-87 public key and signature. It is streamed into the
/// Caliptra mailbox and never occupies the scratch pool, so it costs no memory
/// here, but [`MAX_SPDM_MSG_SIZE`] must still admit it.
const MAX_STREAMED_VDM_REQUEST_LEN: usize =
    caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::LARGE_REQUEST_FRAMING_LEN
        + core::mem::size_of::<mcu_caliptra_api_lite::mailbox::ProductionAuthDebugUnlockToken>();

/// Conservative upper bound on transport MTU. The real MTU is a runtime
/// transport property, so the budget uses a declared ceiling instead.
const MAX_TRANSPORT_MTU: usize = 1024;

/// Pool-resident state that survives across requests once a secure session is
/// established: the `SessionInfo` box (key schedule holds up to nine 128-byte
/// CMKs) plus the VCA / M1 / L1 / TH hash contexts (200 bytes each, one slot
/// run apiece). Measured at roughly 2.3 KiB; rounded up for slot granularity.
const SESSION_WORKING_SET: usize = 2560;

/// Peak transient mailbox/DPE/SHA working set, measured during `certify_key`
/// kid computation.
///
/// This is the one term in the budget that cannot be derived from a declared
/// constant; it must be re-measured if the certificate or DPE paths change.
const TRANSIENT_MAILBOX_PEAK: usize = 2560;

/// Peak concurrent allocation while building a chunked large response: the
/// rented large buffer plus the inline response buffer allocated alongside it.
///
/// The receive buffer is not counted: it is shrunk to the actual frame length
/// immediately after receive, and the request that triggers a large response
/// is always a single small frame.
const LARGE_MSG_PATH_PEAK: usize = MAX_SPDM_MSG_SIZE + MAX_TRANSPORT_MTU;

/// Peak concurrent allocation on the certificate / secure-session path: the
/// mailbox working set plus the secured-message plaintext and ciphertext
/// staging buffers.
const CRYPTO_PATH_PEAK: usize = TRANSIENT_MAILBOX_PEAK + 2 * MAX_TRANSPORT_MTU;

/// Minimum scratch pool that can satisfy [`MAX_SPDM_MSG_SIZE`].
///
/// The two request paths are mutually exclusive: a single request either
/// builds a large chunked response or runs the certificate/crypto path, never
/// both. Likewise the stack rents exactly one large buffer, for a `CHUNK_SEND`
/// reassembly or a `CHUNK_GET` response but not both. So the transient term is
/// a max, not a sum, laid on top of the session state that persists across
/// requests.
const fn required_scratch() -> usize {
    let transient_peak = if LARGE_MSG_PATH_PEAK > CRYPTO_PATH_PEAK {
        LARGE_MSG_PATH_PEAK
    } else {
        CRYPTO_PATH_PEAK
    };
    SESSION_WORKING_SET + transient_peak
}

/// Bitmap allocator pool size per responder task.
///
/// MCTP hosts Caliptra VDM and must hold a buffered large request while its
/// handler uses transient DPE/SHA mailbox workspaces.
const MCTP_SPDM_SCRATCH_SIZE: usize = {
    let declared = 12 * 1024;
    assert!(
        declared >= required_scratch(),
        "MCTP SPDM scratch pool is too small for the configured MAX_SPDM_MSG_SIZE"
    );
    declared
};
/// DOE needs room for measurement records and secure-session crypto workspaces.
const DOE_SPDM_SCRATCH_SIZE: usize = {
    let declared = 12 * 1024;
    assert!(
        declared >= required_scratch(),
        "DOE SPDM scratch pool is too small for the configured MAX_SPDM_MSG_SIZE"
    );
    declared
};

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
fn measurement_provider(
) -> caliptra_mcu_spdm_pal::measurements::providers::pcr_quote::PcrQuoteMeasurementProvider {
    caliptra_mcu_spdm_pal::measurements::providers::pcr_quote::PcrQuoteMeasurementProvider::new()
}

#[cfg(not(feature = "test-mctp-spdm-attestation-pcr-quote"))]
fn measurement_provider(
) -> caliptra_mcu_spdm_pal::measurements::providers::ocp_eat::OcpEatMeasurementProvider {
    caliptra_mcu_spdm_pal::measurements::providers::ocp_eat::OcpEatMeasurementProvider::new(
        caliptra_mcu_spdm_pal::cert::DPE_LEAF_LABEL,
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

/// Spawn SPDM responder tasks on the given executor.
pub(crate) fn spawn_spdm_tasks(spawner: &Spawner) {
    let mut cw = Console::<DefaultSyscalls>::writer();

    if spawner.spawn(spdm_mctp_responder()).is_err() {
        crate::log_error!(cw, "SPDM: Failed to spawn MCTP responder");
    }
    #[cfg(feature = "doe")]
    {
        if spawner.spawn(spdm_doe_responder()).is_err() {
            crate::log_error!(cw, "SPDM: Failed to spawn DOE responder");
        }
    }
}

#[embassy_executor::task]
async fn spdm_mctp_responder() {
    let mut cw = Console::<DefaultSyscalls>::writer();

    #[repr(C, align(64))]
    struct ScratchBuf([u8; MCTP_SPDM_SCRATCH_SIZE]);
    static mut MCTP_SCRATCH: ScratchBuf = ScratchBuf([0u8; MCTP_SPDM_SCRATCH_SIZE]);
    // SAFETY: this task is the sole owner of `MCTP_SCRATCH`.
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(MCTP_SCRATCH.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    // SAFETY: `init_once` is called once per task lifetime; this is the
    // MCTP responder task. Backing memory (`MCTP_SCRATCH`) is `'static`.
    static MCTP_ALLOC_CELL: StaticBitmapAllocatorCell = StaticBitmapAllocatorCell::new();
    let allocator: &'static BitmapAllocator =
        unsafe { MCTP_ALLOC_CELL.init_once(scratch_ptr, MCTP_SPDM_SCRATCH_SIZE) };

    {
        if let Err(e) = ensure_cert_store_init(allocator).await {
            crate::log_error!(
                cw,
                "SPDM_MCTP: cert store init failed: 0x{}",
                crate::Hex32(u32::from(e))
            );
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
    let pal = unsafe {
        McuSpdmPal::new(
            transport,
            allocator,
            &CERT_STORE,
            measurement_provider(),
            MAX_SPDM_MSG_SIZE,
        )
    };
    // MCTP hosts the IANA / Caliptra VDM backend (plaintext today). DOE uses
    // the default NoVdmBackend unless the TDISP/IDE validator feature wires PCI-SIG.
    static COMMANDS: crate::caliptra_cmd_handler::CaliptraCmdBackend =
        crate::caliptra_cmd_handler::CaliptraCmdBackend;
    static STREAM: caliptra_vdm::CaliptraVdmStreamHook = caliptra_vdm::CaliptraVdmStreamHook;
    static AUTHORIZATION: caliptra_vdm::CaliptraVdmAuthorizationHook =
        caliptra_vdm::CaliptraVdmAuthorizationHook;
    let vdm = caliptra_vdm::AppVdmBackend::enabled(&COMMANDS, &STREAM, &AUTHORIZATION);
    let mut stack = SpdmStack::<_, 1, _>::with_vdm_backend(pal, vdm);

    crate::log_info!(cw, "SPDM_MCTP: starting spdm-lib MCTP run loop");
    if let Err(e) = stack.run().await {
        crate::log_error!(
            cw,
            "SPDM_MCTP: MCTP run loop exited: 0x{}",
            crate::Hex32(u32::from(e))
        );
    }
}

#[cfg(feature = "doe")]
#[embassy_executor::task]
async fn spdm_doe_responder() {
    let mut cw = Console::<DefaultSyscalls>::writer();

    let doe_transport = McuSpdmDoeTransport::new(doe::driver_num::DOE_SPDM);
    if !doe_transport.exists() {
        crate::log_info!(cw, "SPDM_DOE: No DOE device, exiting");
        return;
    }

    #[repr(C, align(64))]
    struct ScratchBuf([u8; DOE_SPDM_SCRATCH_SIZE]);
    static mut DOE_SCRATCH: ScratchBuf = ScratchBuf([0u8; DOE_SPDM_SCRATCH_SIZE]);
    // SAFETY: this task is the sole owner of `DOE_SCRATCH`.
    let scratch_ptr: NonNull<u8> = unsafe { NonNull::new_unchecked(DOE_SCRATCH.0.as_mut_ptr()) };
    debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

    // SAFETY: `init_once` is called once per task lifetime; this is the
    // DOE responder task. Backing memory (`DOE_SCRATCH`) is `'static`.
    static DOE_ALLOC_CELL: StaticBitmapAllocatorCell = StaticBitmapAllocatorCell::new();
    let allocator: &'static BitmapAllocator =
        unsafe { DOE_ALLOC_CELL.init_once(scratch_ptr, DOE_SPDM_SCRATCH_SIZE) };

    {
        if let Err(e) = ensure_cert_store_init(allocator).await {
            crate::log_error!(
                cw,
                "SPDM_DOE: cert store init failed: 0x{}",
                crate::Hex32(u32::from(e))
            );
            return;
        }
    }

    let transport = alloc::boxed::Box::new(doe_transport);
    // SAFETY: `allocator` is the `&'static` handle obtained above and is
    // exclusive to this task.
    let pal = unsafe {
        McuSpdmPal::new(
            transport,
            allocator,
            &CERT_STORE,
            measurement_provider(),
            MAX_SPDM_MSG_SIZE,
        )
    };
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
    let mut stack =
        SpdmStack::<_, 1, _>::with_vdm_backend(pal, caliptra_vdm::AppVdmBackend::disabled());

    crate::log_info!(cw, "SPDM_DOE: starting spdm-lib DOE run loop");
    if let Err(e) = stack.run().await {
        crate::log_error!(
            cw,
            "SPDM_DOE: DOE run loop exited: 0x{}",
            crate::Hex32(u32::from(e))
        );
    }
}
