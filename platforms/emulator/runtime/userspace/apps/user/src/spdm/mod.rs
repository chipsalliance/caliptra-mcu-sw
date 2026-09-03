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

/// Scratch-backed limit for large messages retained in full.
///
/// It contributes to `MaxSPDMmsgSize` only when buffered large requests are
/// enabled. Raising it requires larger scratch pools.
const MAX_BUFFERED_SPDM_MSG_SIZE: usize = {
    let declared = 8 * 1024;
    assert!(
        declared
            >= caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::large_response_capacity::<
                crate::caliptra_cmd_handler::CaliptraCmdBackend,
            >(),
        "SPDM scratch capacity is smaller than the largest buffered VDM response; raise \
         MAX_BUFFERED_SPDM_MSG_SIZE and both responder scratch pools"
    );
    declared
};

/// Endpoint-wide logical request limit advertised as `MaxSPDMmsgSize`.
///
/// This is the maximum across buffered and streamed inbound request paths.
const MAX_INBOUND_SPDM_REQUEST_SIZE: usize = {
    let mut required = MAX_TRANSPORT_MTU;
    if MAX_BUFFERED_SPDM_REQUEST_LEN > required {
        required = MAX_BUFFERED_SPDM_REQUEST_LEN;
    }
    if MAX_STREAMED_SPDM_REQUEST_LEN > required {
        required = MAX_STREAMED_SPDM_REQUEST_LEN;
    }
    required
};

/// Maximum across scratch-backed request handlers. Add new buffered request
/// limits to this block.
const MAX_BUFFERED_SPDM_REQUEST_LEN: usize = {
    let mut required = 0;
    if MAX_BUFFERED_VDM_REQUEST_LEN > required {
        required = MAX_BUFFERED_VDM_REQUEST_LEN;
    }
    required
};

/// Logical request ceiling for generic VDM CHUNK_SEND reassembly.
///
/// Caliptra `AuthorizedCommand` requests are retained here in full before VDM
/// dispatch. Streamed debug-unlock and SET_CERTIFICATE requests bypass this
/// buffer. Raise this together with both SPDM scratch pools when a buffered
/// request grows, or add a streaming handler instead.
const MAX_BUFFERED_VDM_REQUEST_LEN: usize = MAX_BUFFERED_SPDM_MSG_SIZE;
const _: () = assert!(
    MAX_BUFFERED_VDM_REQUEST_LEN
        >= caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::
            MAX_AUTHORIZED_COMMAND_SPDM_REQUEST_LEN,
    "buffered SPDM request capacity is smaller than an AuthorizedCommand request"
);

/// Maximum across streaming request handlers. Add new streamed request limits
/// to this block.
const MAX_STREAMED_SPDM_REQUEST_LEN: usize = {
    #[cfg(feature = "test-mctp-spdm-set-certificate")]
    {
        if MAX_STREAMED_SET_CERTIFICATE_REQUEST_LEN > MAX_STREAMED_VDM_REQUEST_LEN {
            MAX_STREAMED_SET_CERTIFICATE_REQUEST_LEN
        } else {
            MAX_STREAMED_VDM_REQUEST_LEN
        }
    }

    #[cfg(not(feature = "test-mctp-spdm-set-certificate"))]
    {
        MAX_STREAMED_VDM_REQUEST_LEN
    }
};

/// Maximum logical size of the streamed debug-unlock VDM request.
const MAX_STREAMED_VDM_REQUEST_LEN: usize =
    caliptra_mcu_spdm_vdm_handler::iana::ocp::caliptra_vdm::SPDM_REQUEST_FRAMING_LEN
        + core::mem::size_of::<mcu_caliptra_api::mailbox::ProductionAuthDebugUnlockToken>();

/// Maximum streamed SET_CERTIFICATE request for a CertChain.
///
/// This limit is tunable based on the integrator's requirements.
#[cfg(feature = "test-mctp-spdm-set-certificate")]
const MAX_STANDARD_CERT_CHAIN_LEN: usize = u16::MAX as usize;
#[cfg(feature = "test-mctp-spdm-set-certificate")]
const MAX_STREAMED_SET_CERTIFICATE_REQUEST_LEN: usize = caliptra_mcu_spdm_codec::SpdmMsgHdrPdu::SIZE
    + caliptra_mcu_spdm_codec::SetCertificateReqBody::SIZE
    + MAX_STANDARD_CERT_CHAIN_LEN;

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
const LARGE_MSG_PATH_PEAK: usize = MAX_BUFFERED_SPDM_MSG_SIZE + MAX_TRANSPORT_MTU;

/// Peak concurrent allocation on the certificate / secure-session path: the
/// mailbox working set plus the secured-message plaintext and ciphertext
/// staging buffers.
const CRYPTO_PATH_PEAK: usize = TRANSIENT_MAILBOX_PEAK + 2 * MAX_TRANSPORT_MTU;

/// Peak mailbox allocation held alongside a buffered SPDM response while
/// producing an ML-DSA-87 signature. DPE signing concurrently owns its
/// 192-byte rounded request and 4,672-byte rounded response allocations.
const MLDSA_SIGN_TRANSIENT_PEAK: usize = 5 * 1024;

/// ML-DSA Challenge and Measurements sign directly into the retained large
/// response, so the response and DPE signing workspace are live together.
const LARGE_RESPONSE_MLDSA_PATH_PEAK: usize =
    MAX_BUFFERED_SPDM_MSG_SIZE + MLDSA_SIGN_TRANSIENT_PEAK;

/// Minimum scratch pool that can satisfy [`MAX_BUFFERED_SPDM_MSG_SIZE`].
///
/// The two request paths are mutually exclusive: a single request either
/// builds a large chunked response or runs the certificate/crypto path, never
/// both. Likewise the stack rents exactly one large buffer, for a `CHUNK_SEND`
/// reassembly or a `CHUNK_GET` response but not both. So the transient term is
/// a max, not a sum, laid on top of the session state that persists across
/// requests.
const fn required_scratch() -> usize {
    let mut transient_peak = if LARGE_MSG_PATH_PEAK > CRYPTO_PATH_PEAK {
        LARGE_MSG_PATH_PEAK
    } else {
        CRYPTO_PATH_PEAK
    };
    if LARGE_RESPONSE_MLDSA_PATH_PEAK > transient_peak {
        transient_peak = LARGE_RESPONSE_MLDSA_PATH_PEAK;
    }
    SESSION_WORKING_SET + transient_peak
}

/// Bitmap allocator pool size per responder task.
///
/// MCTP hosts Caliptra VDM and must hold a buffered large request while its
/// handler uses transient DPE/SHA mailbox workspaces.
const MCTP_SPDM_SCRATCH_SIZE: usize = {
    let declared = 16 * 1024;
    assert!(
        declared >= required_scratch(),
        "MCTP SPDM scratch pool is too small for MAX_BUFFERED_SPDM_MSG_SIZE"
    );
    declared
};
/// DOE needs room for measurement records and secure-session crypto workspaces.
const DOE_SPDM_SCRATCH_SIZE: usize = {
    let declared = 16 * 1024;
    assert!(
        declared >= required_scratch(),
        "DOE SPDM scratch pool is too small for MAX_BUFFERED_SPDM_MSG_SIZE"
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
            MAX_INBOUND_SPDM_REQUEST_SIZE,
            MAX_BUFFERED_SPDM_MSG_SIZE,
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

    let transport = alloc::boxed::Box::new(doe_transport);
    // SAFETY: `allocator` is the `&'static` handle obtained above and is
    // exclusive to this task.
    let pal = unsafe {
        McuSpdmPal::new(
            transport,
            allocator,
            crate::cert_store::shared(),
            measurement_provider(),
            MAX_INBOUND_SPDM_REQUEST_SIZE,
            MAX_BUFFERED_SPDM_MSG_SIZE,
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
