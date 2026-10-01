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
use crate::boot_scratch::BootScratch;
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
#[cfg(feature = "cert-provisioning")]
const MAX_BUFFERED_SPDM_MSG_SIZE: usize = {
    let declared = 14 * 1024;
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

#[cfg(not(feature = "cert-provisioning"))]
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

const fn scratch_alloc_size(size: usize) -> usize {
    size.div_ceil(BITMAP_SLOT_SIZE) * BITMAP_SLOT_SIZE
}

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
/// rented large buffer, the inline response buffer allocated alongside it, and
/// the PQC signing working set.
///
/// The receive buffer is not counted: it is shrunk to the actual frame length
/// immediately after receive, and the request that triggers a large response
/// is always a single small frame.
///
/// ML-DSA-87 signatures (4627 bytes) exceed the MTU, so the response is
/// built in a rented large buffer that is active while signing.
const LARGE_MSG_PATH_PEAK: usize =
    MAX_BUFFERED_SPDM_MSG_SIZE + MAX_TRANSPORT_MTU + PQC_SIGNING_PEAK;

/// Peak DPE working set during ML-DSA-87 signing, including bitmap slot rounding.
const PQC_SIGNING_PEAK: usize =
    mcu_caliptra_api::DPE_MLDSA87_SIGN_SCRATCH_PEAK + 4 * BITMAP_SLOT_SIZE;

/// Peak concurrent allocation on the certificate / secure-session path: the
/// mailbox working set plus the secured-message plaintext and ciphertext
/// staging buffers.
const CRYPTO_PATH_PEAK: usize = TRANSIENT_MAILBOX_PEAK + 2 * MAX_TRANSPORT_MTU;

/// Logical size of an ML-KEM-1024 KEY_EXCHANGE request.
///
/// At 1568 bytes of `ExchangeData` this always exceeds the transport MTU, so the
/// request arrives via `CHUNK_SEND` and is reassembled into a rented buffer.
const MAX_KEY_EXCHANGE_REQ_LEN: usize = caliptra_mcu_spdm_codec::SpdmMsgHdrPdu::SIZE
    + core::mem::size_of::<caliptra_mcu_spdm_codec::KeyExchangeReqBodyFixed>()
    + caliptra_mcu_spdm_codec::MAX_EXCHANGE_DATA_SIZE
    + 2 // OpaqueDataLength
    + caliptra_mcu_spdm_codec::MAX_SUPPORTED_VERSION_LIST_OPAQUE_SIZE;

/// Logical size of the largest KEY_EXCHANGE_RSP: ML-KEM-1024 exchange data
/// signed with ML-DSA-87.
///
/// Fixed body (6) + RandomData + ExchangeData + MeasurementSummaryHash +
/// OpaqueDataLength + OpaqueData + Signature + ResponderVerifyData. At 6347
/// bytes it always exceeds the MTU and is built in a rented large buffer, then
/// served through `CHUNK_GET`.
const MAX_KEY_EXCHANGE_RSP_LEN: usize = caliptra_mcu_spdm_codec::SpdmMsgHdrPdu::SIZE
    + caliptra_mcu_spdm_codec::KEY_EXCHANGE_RSP_FIXED_BODY_SIZE
    + caliptra_mcu_spdm_codec::MAX_EXCHANGE_DATA_SIZE
    + caliptra_mcu_spdm_codec::SHA384_HASH_SIZE
    + 2
    + caliptra_mcu_spdm_codec::OPAQUE_VERSION_SELECTION_SIZE
    + caliptra_mcu_spdm_codec::MLDSA87_SIGNATURE_SIZE
    + caliptra_mcu_spdm_codec::SHA384_HASH_SIZE;

/// Maximum temporary DMTF measurement block used to compute the KEY_EXCHANGE
/// measurement summary hash.
const MAX_MEASUREMENT_SUMMARY_BLOCK_LEN: usize = caliptra_mcu_spdm_codec::MEAS_BLOCK_METADATA_SIZE
    + caliptra_mcu_attestation_evidence::SIGNED_OCP_EAT_MAX_SIZE;

/// Transient peak while generating a KEY_EXCHANGE measurement summary.
///
/// The large response has not been rented yet. The reassembled request, final
/// receive frame, summary output, signed OCP EAT block, and the provider's DPE
/// signing working set coexist.
const KEY_EXCHANGE_MEASUREMENT_PHASE: usize = scratch_alloc_size(MAX_KEY_EXCHANGE_REQ_LEN)
    + scratch_alloc_size(MAX_TRANSPORT_MTU)
    + scratch_alloc_size(caliptra_mcu_spdm_codec::SHA384_HASH_SIZE)
    + scratch_alloc_size(MAX_MEASUREMENT_SUMMARY_BLOCK_LEN)
    + PQC_SIGNING_PEAK;

/// Transient peak while encapsulating a chunked ML-KEM KEY_EXCHANGE.
///
/// The response owns the ciphertext destination. The already-computed summary
/// hash remains live, and the mailbox request and response are additional
/// allocations during encapsulation.
const KEY_EXCHANGE_ENCAPS_PHASE: usize = scratch_alloc_size(MAX_KEY_EXCHANGE_REQ_LEN)
    + scratch_alloc_size(MAX_KEY_EXCHANGE_RSP_LEN)
    + scratch_alloc_size(MAX_TRANSPORT_MTU)
    + scratch_alloc_size(caliptra_mcu_spdm_codec::SHA384_HASH_SIZE)
    + scratch_alloc_size(mcu_caliptra_api::MLKEM_ENCAPSULATE_REQ_SIZE)
    + scratch_alloc_size(mcu_caliptra_api::MLKEM_ENCAPSULATE_RSP_SIZE);

/// Transient peak while signing.
///
/// The reassembled request is released after it is added to the transcript and
/// the KEY_EXCHANGE path does not allocate the generic `CHUNK_SEND_ACK` staging
/// buffer. Only the receive frame, response, handler workspace, and signing
/// working set remain.
const KEY_EXCHANGE_SIGNING_PHASE: usize = scratch_alloc_size(MAX_TRANSPORT_MTU)
    + scratch_alloc_size(MAX_KEY_EXCHANGE_RSP_LEN)
    + scratch_alloc_size(caliptra_mcu_spdm_stack::KEY_EXCHANGE_WORKSPACE_SIZE)
    + PQC_SIGNING_PEAK;

/// Peak concurrent allocation while handling a chunked ML-KEM KEY_EXCHANGE.
///
/// Measurement generation, encapsulation, and signing are sequential, so the
/// transient term is the largest phase.
const KEY_EXCHANGE_CRYPTO_PHASE: usize = if KEY_EXCHANGE_SIGNING_PHASE > KEY_EXCHANGE_ENCAPS_PHASE {
    KEY_EXCHANGE_SIGNING_PHASE
} else {
    KEY_EXCHANGE_ENCAPS_PHASE
};
const KEY_EXCHANGE_CHUNKED_PEAK: usize =
    if KEY_EXCHANGE_MEASUREMENT_PHASE > KEY_EXCHANGE_CRYPTO_PHASE {
        KEY_EXCHANGE_MEASUREMENT_PHASE
    } else {
        KEY_EXCHANGE_CRYPTO_PHASE
    };

/// Minimum scratch pool for a responder task, independent of transport.
///
/// The request paths are mutually exclusive: a single request either builds a
/// large chunked response or runs the certificate/crypto path, never both. So
/// the transient term is a max, not a sum, laid on top of the session state
/// that persists across requests.
///
/// This excludes KEY_EXCHANGE, which only a transport with secured-message
/// support can reach; see [`required_session_scratch`].
const fn required_scratch() -> usize {
    let transient_peak = if LARGE_MSG_PATH_PEAK > CRYPTO_PATH_PEAK {
        LARGE_MSG_PATH_PEAK
    } else {
        CRYPTO_PATH_PEAK
    };
    SESSION_WORKING_SET + transient_peak
}

/// Minimum scratch pool for a responder task whose transport carries secured
/// messages, and can therefore negotiate a key exchange.
///
/// Adds [`KEY_EXCHANGE_CHUNKED_PEAK`] to the paths in [`required_scratch`].
/// Chunked KEY_EXCHANGE releases its reassembled request before signing its
/// buffered response.
///
/// MCTP does not need this: its transport has no secured messages, so
/// NEGOTIATE_ALGORITHMS selects neither DHE nor KEM, and the KEY_EXCHANGE
/// handler rejects the request before allocating anything beyond the
/// reassembled request.
const fn required_session_scratch() -> usize {
    let key_exchange = SESSION_WORKING_SET + KEY_EXCHANGE_CHUNKED_PEAK;
    if key_exchange > required_scratch() {
        key_exchange
    } else {
        required_scratch()
    }
}

/// Bitmap allocator pool size per responder task.
///
/// MCTP hosts Caliptra VDM and must hold a buffered large request while its
/// handler uses transient DPE/SHA mailbox workspaces.
#[cfg(feature = "cert-provisioning")]
const MCTP_SPDM_SCRATCH_SIZE: usize = {
    let declared = 24 * 1024;
    assert!(
        declared >= required_scratch(),
        "MCTP SPDM scratch pool is too small for required_scratch()"
    );
    declared
};

#[cfg(not(feature = "cert-provisioning"))]
const MCTP_SPDM_SCRATCH_SIZE: usize = {
    let declared = 17 * 1024;
    assert!(
        declared >= required_scratch(),
        "MCTP SPDM scratch pool is too small for required_scratch()"
    );
    declared
};

/// DOE needs room for measurement records and secure-session crypto workspaces,
/// including the chunked ML-KEM / ML-DSA-87 KEY_EXCHANGE path.
#[cfg(feature = "cert-provisioning")]
const DOE_SPDM_SCRATCH_SIZE: usize = {
    let declared = 24 * 1024;
    assert!(
        declared >= required_session_scratch(),
        "DOE SPDM scratch pool is too small for required_session_scratch()"
    );
    declared
};

#[cfg(not(feature = "cert-provisioning"))]
const DOE_SPDM_SCRATCH_SIZE: usize = {
    let declared = 18 * 1024;
    assert!(
        declared >= required_session_scratch(),
        "DOE SPDM scratch pool is too small for required_session_scratch()"
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

#[repr(C, align(64))]
struct MctpScratch([u8; MCTP_SPDM_SCRATCH_SIZE]);

/// MCTP responder pool, borrowed during boot initialization before the responder starts.
static mut MCTP_SCRATCH: MctpScratch = MctpScratch([0u8; MCTP_SPDM_SCRATCH_SIZE]);

const _: () = assert!(
    MCTP_SPDM_SCRATCH_SIZE >= crate::cert_store::BOOT_SCRATCH_SIZE,
    "MCTP SPDM scratch pool is too small for certificate-store boot"
);

/// Borrows the idle MCTP task pool for boot initialization.
///
/// # Safety
///
/// Call only before the MCTP responder starts, and move the returned owner into
/// [`spawn_spdm_tasks`] after boot initialization. Do not create another owner
/// while the returned value is alive.
pub(crate) unsafe fn borrow_boot_scratch() -> BootScratch {
    // SAFETY: the pool is 64-byte aligned, and the caller keeps the responder
    // from starting until ownership is moved into it.
    BootScratch::new(
        NonNull::new_unchecked(core::ptr::addr_of_mut!(MCTP_SCRATCH).cast::<u8>()),
        MCTP_SPDM_SCRATCH_SIZE,
    )
}

/// Spawn SPDM responder tasks after [`crate::cert_store::boot_init`] succeeds,
/// consuming the boot owner before the MCTP responder starts.
pub(crate) fn spawn_spdm_tasks(spawner: &Spawner, boot_owner: BootScratch) {
    let mut cw = Console::<DefaultSyscalls>::writer();

    // Dropping `BootScratch` zeroizes the borrowed static pool before the
    // responder reuses it.
    drop(boot_owner);

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

    // SAFETY: `spawn_spdm_tasks` dropped the sole boot owner before scheduling
    // this task, so the responder is now the sole owner of `MCTP_SCRATCH`.
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
