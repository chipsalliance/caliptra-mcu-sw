// Licensed under the Apache-2.0 license

//! User-app SPDM responder — runs spdm-lib over MCTP and DOE.
//!
//! spdm-lib implements version/capability/algorithm negotiation,
//! digests, certificate retrieval, challenge authentication, and SPDM
//! large-message chunking.

extern crate alloc;

mod caliptra_vdm;
#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
mod pci_sig_vdm;

#[cfg(feature = "test-doe-spdm-tdisp-ide-validator")]
use self::pci_sig_vdm::{emulated_ide_km::EmulatedIdeDriver, emulated_tdisp::EmulatedTdispDriver};
#[cfg(feature = "doe")]
use caliptra_mcu_libsyscall_caliptra::doe;
use caliptra_mcu_libsyscall_caliptra::mci::Mci;
use caliptra_mcu_libsyscall_caliptra::mctp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_scratch_alloc::{BitmapAllocator, StaticBitmapAllocatorCell, BITMAP_SLOT_SIZE};
use caliptra_mcu_spdm_pal::McuSpdmPal;
use caliptra_mcu_spdm_stack::SpdmStack;
#[cfg(feature = "ocp-nvme-profile")]
use caliptra_mcu_spdm_traits::SpdmPalTransport;
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
use embassy_executor::Spawner;

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
        + core::mem::size_of::<mcu_caliptra_api::mailbox::ProductionAuthDebugUnlockToken>();

/// Conservative upper bound on transport MTU. The real MTU is a runtime
/// transport property, so the budget uses a declared ceiling instead.
///
/// The `ocp-nvme-profile` feature configures a 4 KiB DOE `DataTransferSize`
/// (OCP 2.7 SPDM-14), so the ceiling — and the scratch budget derived from it —
/// rises to match. The default remains 1024.
#[cfg(feature = "ocp-nvme-profile")]
const MAX_TRANSPORT_MTU: usize = 4096;
#[cfg(not(feature = "ocp-nvme-profile"))]
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

/// Declared per-responder scratch pool size.
///
/// The default 12 KiB is the compact footprint. At a 4 KiB transport MTU the
/// large-message and crypto paths need more headroom (see [`required_scratch`]),
/// so the `ocp-nvme-profile` feature grows the pools to 20 KiB — the cost of
/// keeping CHUNK advertised at a 4 KiB DataTransferSize is ~8 KiB BSS per
/// responder task.
///
/// This is only the reference app's OCP NVMe demonstration profile. Sizing is
/// an integrator decision: the reusable libraries expose the transfer-size and
/// allocator APIs, so an integrator configures its own pool directly rather
/// than through this feature.
#[cfg(feature = "ocp-nvme-profile")]
const DECLARED_SPDM_SCRATCH_SIZE: usize = 20 * 1024;
#[cfg(not(feature = "ocp-nvme-profile"))]
const DECLARED_SPDM_SCRATCH_SIZE: usize = 12 * 1024;

/// MCTP hosts Caliptra VDM and must hold a buffered large request while its
/// handler uses transient DPE/SHA mailbox workspaces.
const MCTP_SPDM_SCRATCH_SIZE: usize = {
    let declared = DECLARED_SPDM_SCRATCH_SIZE;
    assert!(
        declared >= required_scratch(),
        "MCTP SPDM scratch pool is too small for the configured MAX_SPDM_MSG_SIZE"
    );
    declared
};
/// DOE needs room for measurement records and secure-session crypto workspaces.
const DOE_SPDM_SCRATCH_SIZE: usize = {
    let declared = DECLARED_SPDM_SCRATCH_SIZE;
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

/// Spawn SPDM responder tasks after [`crate::cert_store::boot_init`] succeeds.
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
            crate::cert_store::shared(),
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
    Mci::<DefaultSyscalls>::new()
        .set_spdm_mctp_responder_ready()
        .unwrap();
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

    // OCP Datacenter NVMe SSD SPDM (OCP 2.7 SPDM-14) requires a 4 KiB
    // DataTransferSize; see the Security section of the "OCP Datacenter NVMe
    // SSD Specification v2.7", published under OCP Storage at
    // https://www.opencompute.org/documents/datacenter-nvme-ssd-specification-v2-7-final-pdf-1.
    // That minimum is integrator/profile policy, so this reference app selects
    // it here (behind the `ocp-nvme-profile` feature) rather than baking it into
    // the reusable DOE transport, which carries no profile rule of its own.
    // Without the feature the transport uses its own default DataTransferSize
    // and the stack chunks larger messages as usual.
    #[cfg(feature = "ocp-nvme-profile")]
    let doe_transport = {
        const OCP_MIN_DATA_TRANSFER_SIZE: usize = 4096;
        let doe_transport = McuSpdmDoeTransport::with_transfer_size(
            doe::driver_num::DOE_SPDM,
            OCP_MIN_DATA_TRANSFER_SIZE,
        );
        if !doe_transport.exists() {
            crate::log_info!(cw, "SPDM_DOE: No DOE device, exiting");
            return;
        }
        // Enforce the OCP minimum once at init against the driver-bounded MTU. A
        // short driver MTU exits this task gracefully rather than panicking deep
        // in the transport.
        let doe_mtu = SpdmPalTransport::mtu(&doe_transport);
        if doe_mtu < OCP_MIN_DATA_TRANSFER_SIZE {
            crate::log_info!(
                cw,
                "SPDM_DOE: DataTransferSize 0x{} < OCP min, exiting",
                crate::Hex32(doe_mtu as u32)
            );
            return;
        }
        doe_transport
    };
    #[cfg(not(feature = "ocp-nvme-profile"))]
    let doe_transport = {
        let doe_transport = McuSpdmDoeTransport::new(doe::driver_num::DOE_SPDM);
        if !doe_transport.exists() {
            crate::log_info!(cw, "SPDM_DOE: No DOE device, exiting");
            return;
        }
        doe_transport
    };

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

    let transport = alloc::boxed::Box::new(doe_transport);
    // SAFETY: `allocator` is the `&'static` handle obtained above and is
    // exclusive to this task.
    let pal = unsafe {
        McuSpdmPal::new(
            transport,
            allocator,
            crate::cert_store::shared(),
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
    Mci::<DefaultSyscalls>::new()
        .set_spdm_doe_responder_ready()
        .unwrap();
    if let Err(e) = stack.run().await {
        crate::log_error!(
            cw,
            "SPDM_DOE: DOE run loop exited: 0x{}",
            crate::Hex32(u32::from(e))
        );
    }
}
