// Licensed under the Apache-2.0 license

use arrayvec::ArrayVec;
use caliptra_api::mailbox::{EcdsaVerifyReq, MailboxReqHeader, MailboxRespHeader, MldsaVerifyReq};
use caliptra_mcu_common_commands::{
    CaliptraCmdResult, CaliptraCompletionCode, DEBUG_UNLOCK_CHALLENGE_SIZE,
    DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_mbox_common::messages::HybridSignature;
use mcu_caliptra_api_lite::{
    fe_prog, get_attested_csr_ecc384, get_attested_csr_mldsa87, request_debug_unlock_challenge,
    rng_generate, ApiAlloc, McuErrorCode, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
};
use zerocopy::IntoBytes;

const ALGO_ECC_P384: u32 = 0x0001;
const ALGO_MLDSA87: u32 = 0x0002;

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

pub async fn generate_auth_challenge<A: ApiAlloc>(alloc: &A) -> CaliptraCmdResult<[u8; 32]> {
    let mut challenge = [0u8; 32];
    rng_generate(alloc, &mut challenge)
        .await
        .map_err(map_mcu_err)?;
    Ok(challenge)
}

pub async fn verify_authorized_signatures(
    cmd_id: u32,
    payload: &[u8],
    challenge: &[u8; 32],
    ecc_pub_x: [u8; 48],
    ecc_pub_y: [u8; 48],
    mldsa_pub: [u8; 2592],
    sig: &HybridSignature,
) -> CaliptraCmdResult<()> {
    let mut message = ArrayVec::<u8, 256>::new();
    message
        .try_extend_from_slice(&cmd_id.to_be_bytes())
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;
    message
        .try_extend_from_slice(payload)
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;
    message
        .try_extend_from_slice(challenge)
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;

    let mailbox = Mailbox::new();

    // 1. Verify ECC P-384 Signature using Caliptra Mailbox
    let mut hash = [0u8; 48];
    HashContext::hash_all(HashAlgoType::SHA384, message.as_slice(), &mut hash)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    let mut ecc_req = EcdsaVerifyReq {
        hdr: MailboxReqHeader::default(),
        pub_key_x: ecc_pub_x,
        pub_key_y: ecc_pub_y,
        signature_r: sig.ecc_sig_r,
        signature_s: sig.ecc_sig_s,
        hash,
    };

    let mut ecc_resp = MailboxRespHeader::default();

    let ecc_req_bytes = ecc_req.as_mut_bytes();
    let ecc_resp_bytes = ecc_resp.as_mut_bytes();

    let cmd_ecdsa_verify: u32 = caliptra_api::mailbox::CommandId::ECDSA384_SIGNATURE_VERIFY.into();

    execute_mailbox_cmd(&mailbox, cmd_ecdsa_verify, ecc_req_bytes, ecc_resp_bytes)
        .await
        .map_err(|_| CaliptraCompletionCode::AccessDenied)?;

    // 2. Verify ML-DSA-87 Signature using Caliptra Mailbox
    let mut mldsa_req = MldsaVerifyReq {
        hdr: MailboxReqHeader::default(),
        pub_key: mldsa_pub,
        signature: sig.mldsa_sig,
        message_size: message.len() as u32,
        message: [0u8; caliptra_api::mailbox::MAX_CMB_DATA_SIZE],
    };
    mldsa_req.message[..message.len()].copy_from_slice(message.as_slice());

    let mut mldsa_resp = MailboxRespHeader::default();

    let mldsa_req_bytes = mldsa_req
        .as_bytes_partial_mut()
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let mldsa_resp_bytes = mldsa_resp.as_mut_bytes();

    let cmd_mldsa_verify: u32 = caliptra_api::mailbox::CommandId::MLDSA87_SIGNATURE_VERIFY.into();

    execute_mailbox_cmd(
        &mailbox,
        cmd_mldsa_verify,
        mldsa_req_bytes,
        mldsa_resp_bytes,
    )
    .await
    .map_err(|_| CaliptraCompletionCode::AccessDenied)?;

    Ok(())
}

pub async fn program_field_entropy<A: ApiAlloc>(
    alloc: &A,
    partition: u32,
) -> CaliptraCmdResult<()> {
    fe_prog(alloc, partition).await.map_err(map_mcu_err)
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
