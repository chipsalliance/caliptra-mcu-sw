// Licensed under the Apache-2.0 license

#[cfg(feature = "mcu-mbox-service")]
pub(crate) mod cmd_auth_mock;

use caliptra_mcu_libsyscall_caliptra::system::System;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_platform::ErrorCode;
#[cfg(feature = "mcu-mbox-service")]
use caliptra_mcu_mbox_lib::cmd_interface::McuMboxScratch;
#[cfg(feature = "mcu-mbox-service")]
use caliptra_mcu_scratch_alloc::{
    BitmapAllocator, BitmapBytes, StaticBitmapAllocatorCell, BITMAP_SLOT_SIZE,
};
#[allow(unused_imports)]
use core::fmt::Write;
#[cfg(feature = "mcu-mbox-service")]
use core::ptr::NonNull;
#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::signal::Signal;

#[cfg(feature = "mcu-mbox-service")]
const fn slot_bytes(len: usize) -> usize {
    len.div_ceil(BITMAP_SLOT_SIZE) * BITMAP_SLOT_SIZE
}

/// Peak pool use for paths that exist regardless of `attested-csr`, including
/// the bitmap slot.
///
/// The pool is used as one contiguous prefix: the receive buffer is allocated
/// at `size_of::<McuMailboxReq>()`, shrunk to the request length, then the
/// response and any nested handler allocations follow it.
///
/// * The `McuMailboxReq` allocation made before the request is shrunk.
/// * `MC_GET_ATTESTATION` (OCP EAT, ML-DSA-87): the request, an evidence-sized
///   response, and the DPE ML-DSA-87 sign response. This is the largest
///   path when `attested-csr` is off (12,416 B).
/// * `ocp-lock`: `MC_GET_OCP_LOCK_ENDORSEMENT_CERT` /
///   `MC_GET_OCP_LOCK_EPOCH_KEY_REPORT`: the request, the in-place-sign
///   response buffer, and the ECDSA signer's mailbox buffer (12,224 B). The
///   ML-DSA-87 signer runs in place in the response buffer and allocates
///   nothing more.
/// * `MC_DPE_SIGNER_CONTEXT_CERT`: the request, a response sized for a
///   `DPE_MAX_LEAF_CERT_SIZE` leaf certificate staged in place, and the DPE
///   `DeriveContext` request (≈10.6 KiB). Included so a change to the leaf
///   certificate bound is caught by the asserts below.
///
/// All remaining commands peak below these.
#[cfg(feature = "mcu-mbox-service")]
const BASE_MCU_MBOX_SCRATCH_REQUIRED: usize = {
    use caliptra_mcu_common_commands::CaliptraCmdHandler;
    use caliptra_mcu_mbox_common::messages::{
        DpeSignerContextCertReq, GetAttestationReq, MailboxRespHeaderVarSize, McuMailboxReq,
        McuMailboxResp, GET_ATTESTATION_RESP_PREFIX_LEN,
    };
    use caliptra_mcu_mbox_lib::cmd_interface::DPE_SIGNER_CONTEXT_CERT_RESP_SIZE;

    const fn max_usize(a: usize, b: usize) -> usize {
        if a > b {
            a
        } else {
            b
        }
    }

    let initial_req = BITMAP_SLOT_SIZE + slot_bytes(core::mem::size_of::<McuMailboxReq>());
    let get_attestation = BITMAP_SLOT_SIZE
        + slot_bytes(core::mem::size_of::<GetAttestationReq>())
        + slot_bytes(max_usize(
            core::mem::size_of::<McuMailboxResp>(),
            core::mem::size_of::<MailboxRespHeaderVarSize>()
                + GET_ATTESTATION_RESP_PREFIX_LEN
                + <crate::caliptra_cmd_handler::CaliptraCmdBackend as CaliptraCmdHandler>::MAX_ATTESTATION_EVIDENCE_LEN,
        ))
        + slot_bytes(mcu_caliptra_api::DPE_MLDSA87_SIGN_SCRATCH_PEAK);
    let dpe_signer_context_cert = BITMAP_SLOT_SIZE
        + slot_bytes(core::mem::size_of::<DpeSignerContextCertReq>())
        + slot_bytes(DPE_SIGNER_CONTEXT_CERT_RESP_SIZE)
        + slot_bytes(mcu_caliptra_api::DPE_DERIVE_CONTEXT_EXPORTED_CDI_SCRATCH_PEAK);
    let required = max_usize(
        initial_req,
        max_usize(get_attestation, dpe_signer_context_cert),
    );

    #[cfg(feature = "ocp-lock")]
    let required = {
        use caliptra_api::mailbox::{SignWithExportedEcdsaReq, SignWithExportedEcdsaResp};
        use caliptra_mcu_mbox_common::messages::{
            GetOcpLockEndorsementCertReq, GetOcpLockEpochKeyReportReq,
        };
        use caliptra_mcu_mbox_lib::cmd_interface::OCP_LOCK_IN_PLACE_SIGN_RESP_DATA_SIZE;
        let ocp_lock_signed = BITMAP_SLOT_SIZE
            + slot_bytes(max_usize(
                core::mem::size_of::<GetOcpLockEndorsementCertReq>(),
                core::mem::size_of::<GetOcpLockEpochKeyReportReq>(),
            ))
            + slot_bytes(
                core::mem::size_of::<MailboxRespHeaderVarSize>()
                    + OCP_LOCK_IN_PLACE_SIGN_RESP_DATA_SIZE,
            )
            + slot_bytes(max_usize(
                core::mem::size_of::<SignWithExportedEcdsaReq>(),
                core::mem::size_of::<SignWithExportedEcdsaResp>(),
            ));
        max_usize(required, ocp_lock_signed)
    };

    required
};

/// `MC_EXPORT_ATTESTED_CSR` stages up to 12.8 KiB of CSR in one response, so
/// the pool must hold the bitmap slot, the shrunk request, and that response.
#[cfg(all(feature = "mcu-mbox-service", feature = "attested-csr"))]
const MCU_MBOX_SCRATCH_SIZE: usize = {
    use caliptra_mcu_mbox_common::messages::{ExportAttestedCsrReq, ExportAttestedCsrResp};
    let declared = 13 * 1024;
    let attested_csr = BITMAP_SLOT_SIZE
        + slot_bytes(core::mem::size_of::<ExportAttestedCsrReq>())
        + slot_bytes(core::mem::size_of::<ExportAttestedCsrResp>());
    assert!(
        declared >= attested_csr,
        "MCU_MBOX_SCRATCH_SIZE cannot hold an MC_EXPORT_ATTESTED_CSR request and response"
    );
    assert!(
        declared >= BASE_MCU_MBOX_SCRATCH_REQUIRED,
        "MCU_MBOX_SCRATCH_SIZE cannot hold the MC_GET_ATTESTATION / request-receive peak"
    );
    declared
};

/// Without `attested-csr`, `MC_GET_ATTESTATION` with ML-DSA-87 signing is the
/// peak (12,416 B with the default evidence configuration). 12.5 KiB leaves
/// six spare slots.
#[cfg(all(feature = "mcu-mbox-service", not(feature = "attested-csr")))]
const MCU_MBOX_SCRATCH_SIZE: usize = {
    let declared = 12 * 1024 + 512;
    assert!(
        declared >= BASE_MCU_MBOX_SCRATCH_REQUIRED,
        "MCU_MBOX_SCRATCH_SIZE cannot hold the MC_GET_ATTESTATION / request-receive peak"
    );
    declared
};

#[cfg(feature = "mcu-mbox-service")]
struct McuMboxScratchAlloc(&'static BitmapAllocator);

#[cfg(feature = "mcu-mbox-service")]
impl mcu_caliptra_api::ApiAlloc for McuMboxScratchAlloc {
    type Buf<'a>
        = BitmapBytes<'a>
    where
        Self: 'a;

    fn alloc(&self, len: usize) -> mcu_error::McuResult<Self::Buf<'_>> {
        self.0.alloc_bytes(len)
    }
}

#[cfg(feature = "mcu-mbox-service")]
impl mcu_caliptra_api::ApiAllocPool for McuMboxScratchAlloc {
    type Pool = BitmapAllocator;

    fn pool(&self) -> &Self::Pool {
        self.0
    }
}

#[cfg(feature = "mcu-mbox-service")]
impl McuMboxScratch for McuMboxScratchAlloc {
    fn shrink(buf: &mut BitmapBytes<'_>, new_len: usize) -> mcu_error::McuResult<()> {
        buf.shrink(new_len)
    }
}

#[embassy_executor::task]
pub async fn mcu_mbox_task() {
    match start_mcu_mbox_service().await {
        Ok(_) => {}
        Err(_) => System::exit(1),
    }
}

#[allow(dead_code)]
#[allow(unused_variables)]
async fn start_mcu_mbox_service() -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    crate::log_info!(console_writer, "Starting MCU_MBOX task...");

    #[cfg(feature = "mcu-mbox-service")]
    {
        #[repr(C, align(64))]
        struct ScratchBuf([u8; MCU_MBOX_SCRATCH_SIZE]);
        static mut MCU_MBOX_SCRATCH: ScratchBuf = ScratchBuf([0u8; MCU_MBOX_SCRATCH_SIZE]);
        // SAFETY: this task is the sole owner of `MCU_MBOX_SCRATCH`.
        let scratch_ptr: NonNull<u8> =
            unsafe { NonNull::new_unchecked(MCU_MBOX_SCRATCH.0.as_mut_ptr()) };
        debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

        // SAFETY: `init_once` is called once per task lifetime; backing memory
        // (`MCU_MBOX_SCRATCH`) is `'static` and exclusive to this task.
        static MCU_MBOX_ALLOC_CELL: StaticBitmapAllocatorCell = StaticBitmapAllocatorCell::new();
        let scratch_allocator: &'static BitmapAllocator =
            unsafe { MCU_MBOX_ALLOC_CELL.init_once(scratch_ptr, MCU_MBOX_SCRATCH_SIZE) };
        let scratch = McuMboxScratchAlloc(scratch_allocator);

        // Command handler shared with the MCTP and SPDM VDM backends.
        let handler = crate::caliptra_cmd_handler::CaliptraCmdBackend;
        // Authorizer: HMAC-based command authorization stays wired in production
        // (uses a placeholder test key for now; to be replaced with real
        // provisioned key material later).
        let mut cmd_authorizer = cmd_auth_mock::MockCommandAuthorizer;
        let mut transport = caliptra_mcu_mbox_lib::transport::McuMboxTransport::new(
            caliptra_mcu_libsyscall_caliptra::mcu_mbox::MCU_MBOX0_DRIVER_NUM,
        );
        let mut mcu_mbox_service = caliptra_mcu_mbox_lib::daemon::McuMboxService::init(
            &handler,
            &mut cmd_authorizer,
            &mut transport,
            &scratch,
        );
        crate::log_info!(
            console_writer,
            "Starting MCU_MBOX service for integration tests..."
        );

        if let Err(e) = mcu_mbox_service.start().await {
            crate::log_error!(
                console_writer,
                "USER_APP: Error starting MCU_MBOX service: {}",
                crate::Dbg(e)
            );
        }
        let suspend_signal: Signal<CriticalSectionRawMutex, ()> = Signal::new();
        suspend_signal.wait().await;
    }

    Ok(())
}
