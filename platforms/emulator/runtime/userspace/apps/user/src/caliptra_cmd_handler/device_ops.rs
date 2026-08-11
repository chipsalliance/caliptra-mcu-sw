// Licensed under the Apache-2.0 license

use arrayvec::ArrayVec;
use caliptra_api::mailbox::{EcdsaVerifyReq, MailboxReqHeader, MailboxRespHeader, MldsaVerifyReq};
use caliptra_mcu_attestation_evidence::encode_signed_ocp_eat;
#[cfg(feature = "pcr-quote")]
use caliptra_mcu_attestation_evidence::pcr_quote::{encode_pcr_quote, PcrQuoteAlgorithm};
use caliptra_mcu_common_commands::{
    AsymAlgo, CaliptraCmdResult, CaliptraCompletionCode, EvidenceFormat, GetLogResult, LogType,
    PkiEntitySlot, ATTESTATION_NONCE_LEN, DEBUG_UNLOCK_CHALLENGE_SIZE,
    DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
// The AK label lives with the cert store because that is what mints the leaf
// certificate; attestation evidence must be signed under the same label so the
// leaf cert in the device's chain is the one that verifies it.
use caliptra_mcu_mbox_common::messages::{HybridSignature, AUTH_CMD_NONCE_LEN};
use caliptra_mcu_spdm_pal::cert::DPE_LEAF_LABEL;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use mcu_caliptra_api::{
    get_attested_csr_ecc384, get_attested_csr_mldsa87, get_idev_csr_ecc384, hash_all,
    request_debug_unlock_challenge, sha_finish, sha_init, sha_update, ApiAlloc, HashAlgo,
    McuErrorCode, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN, SHA_CONTEXT_SIZE,
};
// Only used by the SPDM/VDM-gated `generate_auth_challenge` below.
#[cfg(feature = "spdm")]
use mcu_caliptra_api::rng_generate;
use zerocopy::IntoBytes;

const ALGO_ECC_P384: u32 = 0x0001;
const ALGO_MLDSA87: u32 = 0x0002;

pub async fn get_debug_log(log_type: u32, data: &mut [u8]) -> CaliptraCmdResult<GetLogResult> {
    LogType::try_from(log_type)?;
    super::debug_log::drain(data).await
}

pub async fn clear_debug_log(log_type: u32) -> CaliptraCmdResult<()> {
    LogType::try_from(log_type)?;
    super::debug_log::clear().await
}

pub async fn request_debug_unlock<A: ApiAlloc>(
    alloc: &A,
    unlock_level: u8,
    out: &mut [u8],
) -> CaliptraCmdResult<usize> {
    let needed = DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE;
    if out.len() < needed {
        return Err(CaliptraCompletionCode::InsufficientResources);
    }

    request_debug_unlock_challenge(alloc, unlock_level, out)
        .await
        .map_err(map_mcu_err)
}

/// Relay a debug-unlock token to Caliptra.
///
/// The debug-unlock token is (potentially) delivered in streamed chunks, so
/// firmware cannot recompute a `MailboxReqHeader` checksum over data it never
/// fully buffers. The requester therefore supplies the checksum as part of a
/// complete Caliptra RT mailbox request, and both transports (MCU mailbox and
/// SPDM VDM) relay it as a pure pass-through — firmware never synthesizes a
/// header. This differs from other Caliptra commands, whose checksum the lite
/// API builds from in-firmware parameters.
pub async fn authorize_debug_unlock_token<A: ApiAlloc>(
    _alloc: &A,
    token_request: &[u8],
) -> CaliptraCmdResult<()> {
    // 8-byte response header is a write-only throwaway, so use a stack buffer.
    // `_alloc` is kept for a uniform device-op signature but ignored at this size.
    let mut resp_buf = [0u8; PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN];

    Mailbox::<DefaultSyscalls>::new()
        .execute_with_payload_slice(
            PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD,
            None,
            token_request,
            &mut resp_buf,
        )
        .await
        .map_err(map_mailbox_error)?;
    Ok(())
}

pub async fn export_attested_csr(
    device_key_id: u32,
    algorithm: u32,
    nonce: &[u8; 32],
    out: &mut [u8],
) -> CaliptraCmdResult<usize> {
    let result = match algorithm {
        ALGO_ECC_P384 => get_attested_csr_ecc384(device_key_id, nonce, out).await,
        ALGO_MLDSA87 => get_attested_csr_mldsa87(device_key_id, nonce, out).await,
        _ => return Err(CaliptraCompletionCode::InvalidParameter),
    };
    result.map_err(map_mcu_err)
}

/// Generate signed attestation evidence for `GET_ATTESTATION`.
///
/// Unsupported `(format, algorithm)` pairs are rejected by the transports via
/// `CaliptraCmdHandler::attestation_evidence_len` before they reach here; the
/// arms below are the same set, so the two stay consistent.
///
/// Only [`PkiEntitySlot::Vendor`] is served. Signing is not slot-aware yet —
/// every entity resolves to the same vendor DPE leaf — so honoring `Owner`
/// would return evidence claiming an owner endorsement that was never
/// selected or provisioned. It is refused until slot-aware key and
/// certificate selection exists.
pub async fn get_attestation<A: ApiAlloc>(
    alloc: &A,
    format: EvidenceFormat,
    algorithm: AsymAlgo,
    entity: PkiEntitySlot,
    nonce: &[u8; ATTESTATION_NONCE_LEN],
    out: &mut [u8],
) -> CaliptraCmdResult<usize> {
    if entity != PkiEntitySlot::Vendor {
        return Err(CaliptraCompletionCode::UnsupportedOperation);
    }
    match (format, algorithm) {
        // The EAT signer emits only ES384 today, so there is no ML-DSA EAT to
        // dispatch to yet.
        // TODO: add an (OcpEat, Mldsa87) arm when the EAT signer supports
        // ML-DSA-87, and a matching bound in `evidence_len`.
        (EvidenceFormat::OcpEat, AsymAlgo::EccP384) => {
            encode_signed_ocp_eat(alloc, &DPE_LEAF_LABEL, entity as u8, nonce, out)
                .await
                .map_err(map_mcu_err)
        }
        #[cfg(feature = "pcr-quote")]
        (EvidenceFormat::PcrQuote, algo) => {
            let algo = match algo {
                AsymAlgo::EccP384 => PcrQuoteAlgorithm::Ecc384,
                AsymAlgo::Mldsa87 => PcrQuoteAlgorithm::Mldsa87,
            };
            encode_pcr_quote(alloc, algo, Some(nonce), out)
                .await
                .map_err(map_mcu_err)
        }
        _ => Err(CaliptraCompletionCode::UnsupportedOperation),
    }
}

pub async fn export_idevid_csr(algorithm: u32, out: &mut [u8]) -> CaliptraCmdResult<usize> {
    match algorithm {
        ALGO_ECC_P384 => get_idev_csr_ecc384(out)
            .await
            .map_err(map_mcu_err)?
            .ok_or(CaliptraCompletionCode::InvalidState),
        ALGO_MLDSA87 => Err(CaliptraCompletionCode::UnsupportedOperation),
        _ => Err(CaliptraCompletionCode::InvalidParameter),
    }
}

// Only the SPDM/VDM authorization path issues challenges from here; the mailbox
// path generates its own in `mcu-mbox-lib`. Gate to the caller's feature so the
// non-SPDM (mailbox-test) build does not see it as dead code.
#[cfg(feature = "spdm")]
pub async fn generate_auth_challenge<A: ApiAlloc>(
    alloc: &A,
) -> CaliptraCmdResult<[u8; AUTH_CMD_NONCE_LEN]> {
    let mut challenge = [0u8; AUTH_CMD_NONCE_LEN];
    rng_generate(alloc, &mut challenge)
        .await
        .map_err(map_mcu_err)?;
    Ok(challenge)
}

/// Verify a command's dual signatures (ECC P-384 + ML-DSA-87) using the vendor
/// public keys received on the wire. Fail-closed: anchor -> ECDSA -> ML-DSA;
/// any failure returns `AccessDenied`. `challenge` is the wire nonce (already
/// checked against the stored one-time value by the caller).
///
/// Mirrors the prod-debug-unlock authorization idiom: each leg verifies a digest
/// of the raw pre-image = cmd_id(BE,4) || payload || nonce(48). ECDSA verifies
/// over SHA-384(pre-image); ML-DSA verifies over SHA-512(pre-image).
#[allow(clippy::too_many_arguments)]
pub async fn verify_authorized_signatures<A: ApiAlloc>(
    alloc: &A,
    cmd_id: u32,
    payload: &[u8],
    challenge: &[u8; AUTH_CMD_NONCE_LEN],
    ecc_pub_x: &[u8; 48],
    ecc_pub_y: &[u8; 48],
    mldsa_pub: &[u8; 2592],
    sig: &HybridSignature,
) -> CaliptraCmdResult<()> {
    // Anchor: SHA-384(received keys) must equal the embedded AUTH_PK_HASH.
    // Streamed (2688 B exceeds the one-shot hash cap).
    let hash_context = alloc
        .alloc(SHA_CONTEXT_SIZE)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let mut anchor_ctx = sha_init(alloc, hash_context, HashAlgo::Sha384, ecc_pub_x)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    sha_update(alloc, &mut anchor_ctx, ecc_pub_y)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    sha_update(alloc, &mut anchor_ctx, mldsa_pub)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let mut pk_hash = [0u8; 48];
    sha_finish(alloc, &mut anchor_ctx, &mut pk_hash)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    if pk_hash != crate::auth_keys::AUTH_PK_HASH {
        return Err(CaliptraCompletionCode::AccessDenied);
    }

    // Pre-image = cmd_id(BE,4) || payload || nonce(48). Built from the raw payload
    // (no inner hash), mirroring prod-debug-unlock; each leg verifies a digest of it.
    let mut pre_image = ArrayVec::<u8, 256>::new();
    pre_image
        .try_extend_from_slice(&cmd_id.to_be_bytes())
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;
    pre_image
        .try_extend_from_slice(payload)
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;
    pre_image
        .try_extend_from_slice(challenge)
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;

    // ECC P-384 over SHA-384(pre-image) (ECDSA takes a 48-byte digest; matches the
    // host's `sign(&pre_image)`, which hashes the pre-image with SHA-384 internally).
    let mut hash = [0u8; 48];
    hash_all(alloc, HashAlgo::Sha384, pre_image.as_slice(), &mut hash)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    let mut ecc_req = EcdsaVerifyReq {
        hdr: MailboxReqHeader::default(),
        pub_key_x: *ecc_pub_x,
        pub_key_y: *ecc_pub_y,
        signature_r: sig.ecc_sig_r,
        signature_s: sig.ecc_sig_s,
        hash,
    };

    let mut ecc_resp = MailboxRespHeader::default();

    let ecc_req_bytes = ecc_req.as_mut_bytes();
    let ecc_resp_bytes = ecc_resp.as_mut_bytes();

    let cmd_ecdsa_verify: u32 = caliptra_api::mailbox::CommandId::ECDSA384_SIGNATURE_VERIFY.into();

    mcu_caliptra_api::raw::raw_mailbox_execute(cmd_ecdsa_verify, ecc_req_bytes, ecc_resp_bytes)
        .await
        .map_err(|_| CaliptraCompletionCode::AccessDenied)?;

    // ML-DSA-87 over SHA-512(pre-image): the 64-byte digest is the signed message
    // (external pre-hash), matching the host's `try_sign(&SHA-512(pre-image))`.
    let mut mldsa_msg = [0u8; 64];
    hash_all(
        alloc,
        HashAlgo::Sha512,
        pre_image.as_slice(),
        &mut mldsa_msg,
    )
    .await
    .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    // Use a shared static buffer behind an async Mutex to avoid inflating
    // the async task future by ~11 KB.  The guard is held across `.await`.
    // SAFETY: MldsaVerifyReq derives FromBytes, so all-zeros is a valid repr.
    static MLDSA_REQ: Mutex<CriticalSectionRawMutex, core::mem::MaybeUninit<MldsaVerifyReq>> =
        Mutex::new(core::mem::MaybeUninit::zeroed());

    let mut guard = MLDSA_REQ.lock().await;
    // SAFETY: MldsaVerifyReq derives FromBytes — all-zeros (from the static
    // initializer) and any byte pattern we write are valid representations.
    let req: &mut MldsaVerifyReq = unsafe { guard.assume_init_mut() };
    req.hdr = MailboxReqHeader::default();
    req.pub_key = *mldsa_pub;
    req.signature = sig.mldsa_sig;
    req.message_size = mldsa_msg.len() as u32;
    req.message = [0u8; caliptra_api::mailbox::MAX_CMB_DATA_SIZE];
    req.message[..mldsa_msg.len()].copy_from_slice(&mldsa_msg);

    let mldsa_req_bytes = req
        .as_bytes_partial_mut()
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    let mut mldsa_resp = MailboxRespHeader::default();
    let mldsa_resp_bytes = mldsa_resp.as_mut_bytes();

    let cmd_mldsa_verify: u32 = caliptra_api::mailbox::CommandId::MLDSA87_SIGNATURE_VERIFY.into();

    mcu_caliptra_api::raw::raw_mailbox_execute(cmd_mldsa_verify, mldsa_req_bytes, mldsa_resp_bytes)
        .await
        .map_err(|_| CaliptraCompletionCode::AccessDenied)?;

    Ok(())
}

pub(crate) fn map_mcu_err(e: McuErrorCode) -> CaliptraCompletionCode {
    use mcu_error::codes;
    if e == codes::MAILBOX_BUSY {
        CaliptraCompletionCode::CaliptraMailboxBusy
    } else if e == codes::INVARIANT || e == codes::INTERNAL_BUG {
        CaliptraCompletionCode::OperationFailed
    } else if e.domain() == mcu_error::domain::MEMORY {
        CaliptraCompletionCode::InsufficientResources
    } else {
        CaliptraCompletionCode::GeneralError
    }
}

pub(crate) fn map_mailbox_error(e: MailboxError) -> CaliptraCompletionCode {
    match e {
        MailboxError::ErrorCode(ErrorCode::Busy) => CaliptraCompletionCode::CaliptraMailboxBusy,
        MailboxError::ErrorCode(_) | MailboxError::MailboxError(_) => {
            CaliptraCompletionCode::OperationFailed
        }
    }
}
