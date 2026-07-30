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
use caliptra_mcu_mbox_common::messages::{HybridSignature, AUTH_CMD_NONCE_LEN};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use mcu_caliptra_api_lite::{
    fe_prog, get_attested_csr_ecc384, get_attested_csr_mldsa87, get_idev_csr_ecc384,
    request_debug_unlock_challenge, rng_generate, ApiAlloc, McuErrorCode,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
};
use zerocopy::IntoBytes;

const ALGO_ECC_P384: u32 = 0x0001;
const ALGO_MLDSA87: u32 = 0x0002;

// ML-DSA verify message is a fixed 64-byte SHA-512 digest; only the prefix up
// to `message[..64]` is transmitted, so the shared request buffer is sized to
// that instead of the full MldsaVerifyReq (keeps the 4 KB message tail out of .bss).
const MLDSA_VERIFY_DIGEST_LEN: usize = 64;
const MLDSA_VERIFY_REQ_WIRE_LEN: usize =
    core::mem::offset_of!(MldsaVerifyReq, message) + MLDSA_VERIFY_DIGEST_LEN;
// Must equal MldsaVerifyReq::as_bytes_partial_mut() length at message_size=64.
const _: () = assert!(
    MLDSA_VERIFY_REQ_WIRE_LEN
        == core::mem::size_of::<MldsaVerifyReq>()
            - (caliptra_api::mailbox::MAX_CMB_DATA_SIZE - MLDSA_VERIFY_DIGEST_LEN)
);
// The right-size only helps if the buffer is smaller than the full struct.
const _: () = assert!(MLDSA_VERIFY_REQ_WIRE_LEN < core::mem::size_of::<MldsaVerifyReq>());

// Serialize an MLDSA87_SIGNATURE_VERIFY request into `out` at the real
// MldsaVerifyReq field offsets. chksum ([0..pub_key]) is zeroed: the caller's
// populate_checksum() sums the whole slice then overwrites [0..4]; RT verifies
// over [4..], so a nonzero header would break the checksum.
fn build_mldsa_verify_req(
    out: &mut [u8; MLDSA_VERIFY_REQ_WIRE_LEN],
    pub_key: &[u8; 2592],
    signature: &[u8; 4628],
    message: &[u8; MLDSA_VERIFY_DIGEST_LEN],
) {
    const O_PUB_KEY: usize = core::mem::offset_of!(MldsaVerifyReq, pub_key);
    const O_SIGNATURE: usize = core::mem::offset_of!(MldsaVerifyReq, signature);
    const O_MESSAGE_SIZE: usize = core::mem::offset_of!(MldsaVerifyReq, message_size);
    const O_MESSAGE: usize = core::mem::offset_of!(MldsaVerifyReq, message);
    out[..O_PUB_KEY].fill(0);
    out[O_PUB_KEY..O_PUB_KEY + pub_key.len()].copy_from_slice(pub_key);
    out[O_SIGNATURE..O_SIGNATURE + signature.len()].copy_from_slice(signature);
    out[O_MESSAGE_SIZE..O_MESSAGE_SIZE + 4]
        .copy_from_slice(&(MLDSA_VERIFY_DIGEST_LEN as u32).to_le_bytes());
    out[O_MESSAGE..O_MESSAGE + message.len()].copy_from_slice(message);
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

pub async fn generate_auth_challenge<A: ApiAlloc>(
    alloc: &A,
) -> CaliptraCmdResult<[u8; AUTH_CMD_NONCE_LEN]> {
    let mut challenge = [0u8; AUTH_CMD_NONCE_LEN];
    rng_generate(alloc, &mut challenge)
        .await
        .map_err(map_mcu_err)?;
    Ok(challenge)
}

pub async fn verify_authorized_signatures(
    cmd_id: u32,
    payload: &[u8],
    challenge: &[u8; AUTH_CMD_NONCE_LEN],
    ecc_pub_x: [u8; 48],
    ecc_pub_y: [u8; 48],
    mldsa_pub: &[u8; 2592],
    sig: &HybridSignature,
) -> CaliptraCmdResult<()> {
    // Pre-image = cmd_id(BE,4) || payload || challenge(48), built from the raw
    // payload (no inner hash), mirroring prod-debug-unlock. Each leg verifies a
    // digest of it: ECDSA over SHA-384(pre-image), ML-DSA over SHA-512(pre-image).
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

    let mailbox = Mailbox::new();

    // 1. Verify ECC P-384 Signature using Caliptra Mailbox (over SHA-384(pre-image)).
    let mut hash = [0u8; 48];
    HashContext::hash_all(HashAlgoType::SHA384, pre_image.as_slice(), &mut hash)
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

    // 2. Verify ML-DSA-87 Signature using Caliptra Mailbox (over SHA-512(pre-image)).
    let mut mldsa_msg = [0u8; 64];
    HashContext::hash_all(HashAlgoType::SHA512, pre_image.as_slice(), &mut mldsa_msg)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    // Shared static request buffer behind an async Mutex (held across `.await`)
    // so the ~11 KB request is not duplicated into every task's future. Sized
    // to the transmitted prefix (message is a fixed 64-byte digest, not the
    // full MAX_CMB_DATA_SIZE), which keeps ~4 KB out of `.bss` vs storing the
    // whole MldsaVerifyReq. Fields are written at the real struct offsets so
    // the wire image is byte-identical to as_bytes_partial_mut() at
    // message_size=64.
    static MLDSA_REQ: Mutex<CriticalSectionRawMutex, [u8; MLDSA_VERIFY_REQ_WIRE_LEN]> =
        Mutex::new([0u8; MLDSA_VERIFY_REQ_WIRE_LEN]);

    let mut guard = MLDSA_REQ.lock().await;
    build_mldsa_verify_req(&mut guard, mldsa_pub, &sig.mldsa_sig, &mldsa_msg);
    let mldsa_req_bytes = guard.as_mut_slice();

    let mut mldsa_resp = MailboxRespHeader::default();
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

#[cfg(test)]
mod tests {
    use super::*;

    // The right-sized shared buffer must be byte-identical to what the full
    // MldsaVerifyReq would transmit via as_bytes_partial_mut() at message_size=64.
    #[test]
    fn mldsa_verify_req_wire_matches_full_struct() {
        let mut pub_key = [0u8; 2592];
        let mut signature = [0u8; 4628];
        let mut message = [0u8; MLDSA_VERIFY_DIGEST_LEN];
        for (i, b) in pub_key.iter_mut().enumerate() {
            *b = i as u8;
        }
        for (i, b) in signature.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5a;
        }
        for (i, b) in message.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(3);
        }

        let mut got = [0u8; MLDSA_VERIFY_REQ_WIRE_LEN];
        build_mldsa_verify_req(&mut got, &pub_key, &signature, &message);

        let mut full = MldsaVerifyReq {
            hdr: MailboxReqHeader::default(),
            pub_key,
            signature,
            message_size: MLDSA_VERIFY_DIGEST_LEN as u32,
            message: [0u8; caliptra_api::mailbox::MAX_CMB_DATA_SIZE],
        };
        full.message[..MLDSA_VERIFY_DIGEST_LEN].copy_from_slice(&message);
        let want = full.as_bytes_partial_mut().unwrap();

        assert_eq!(want.len(), MLDSA_VERIFY_REQ_WIRE_LEN);
        assert_eq!(got.as_slice(), &*want);
    }

    // chksum field stays zero so populate_checksum() computes correctly.
    #[test]
    fn mldsa_verify_req_checksum_field_zeroed() {
        let mut got = [0xffu8; MLDSA_VERIFY_REQ_WIRE_LEN];
        build_mldsa_verify_req(
            &mut got,
            &[1u8; 2592],
            &[2u8; 4628],
            &[3u8; MLDSA_VERIFY_DIGEST_LEN],
        );
        let chksum_len = core::mem::offset_of!(MldsaVerifyReq, pub_key);
        assert!(got[..chksum_len].iter().all(|&b| b == 0));
    }
}
