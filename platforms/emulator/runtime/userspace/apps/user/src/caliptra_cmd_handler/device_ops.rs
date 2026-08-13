// Licensed under the Apache-2.0 license

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use arrayvec::ArrayVec;
use async_trait::async_trait;
use caliptra_api::mailbox::{EcdsaVerifyReq, MailboxReqHeader, MailboxRespHeader};
use caliptra_mcu_attestation_evidence::encode_signed_ocp_eat;
#[cfg(feature = "pcr-quote")]
use caliptra_mcu_attestation_evidence::pcr_quote::{encode_pcr_quote, PcrQuoteAlgorithm};
use caliptra_mcu_common_commands::{
    AsymAlgo, CaliptraCmdResult, CaliptraCompletionCode, EvidenceFormat, GetLogResult, LogType,
    PkiEntitySlot, ATTESTATION_NONCE_LEN, DEBUG_UNLOCK_CHALLENGE_SIZE,
    DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash;
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError, PayloadStream};
use caliptra_mcu_libsyscall_caliptra::otp::{Otp, RevokeVendorPubKeyType};
use caliptra_mcu_libsyscall_caliptra::{caliptra, otp, DefaultSyscalls};
use caliptra_mcu_libtock_platform::ErrorCode;
// The AK label lives with the cert store because that is what mints the leaf
// certificate; attestation evidence must be signed under the same label so the
// leaf cert in the device's chain is the one that verifies it.
use caliptra_mcu_mbox_common::messages::{
    CommandId, DotDisablePayload, DotLockPayload, DotUnlockPayload, HybridSignature,
    AUTH_CMD_NONCE_LEN, DOT_KEY_HASH_SIZE, DOT_MLDSA_PUBLIC_KEY_SIZE,
};
use caliptra_mcu_registers_generated::fuses;
use caliptra_mcu_spdm_pal::cert::DPE_LEAF_LABEL;
use core::cell::RefCell;
use embassy_sync::blocking_mutex::{raw::CriticalSectionRawMutex, Mutex as BlockingMutex};
use mcu_caliptra_api::{
    cm_hmac_sha512, derive_stable_key, fe_prog, fw_info, get_attested_csr_ecc384,
    get_attested_csr_mldsa87, get_idev_csr_ecc384, hash_all, request_debug_unlock_challenge,
    rng_generate, sha_finish, sha_init, sha_update, ApiAlloc, HashAlgo, McuErrorCode,
    StableKeyType, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN, SHA_CONTEXT_SIZE,
};
use portable_atomic::{AtomicBool, Ordering};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

const ALGO_ECC_P384: u32 = 0x0001;
const ALGO_MLDSA87: u32 = 0x0002;
const DOT_LABEL: &[u8; 23] = b"Caliptra DOT stable key";
const DOT_BLOB_VERSION: u32 = 1;
const DOT_UNLOCK_METHOD_CHALLENGE_RESPONSE: u8 = 1;
const DOT_BLOB_FIELDS_SIZE: usize = 104;
const DOT_HMAC_SIZE: usize = 64;
const DOT_BLOB_SIZE: usize = DOT_BLOB_FIELDS_SIZE + DOT_HMAC_SIZE;

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
struct RuntimeDotBlobFields {
    version: u32,
    cak: [u8; DOT_KEY_HASH_SIZE],
    lak_pub: [u8; DOT_KEY_HASH_SIZE],
    unlock_method: u8,
    reserved: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
struct RuntimeDotBlob {
    fields: RuntimeDotBlobFields,
    hmac: [u8; DOT_HMAC_SIZE],
}

const _: [(); DOT_BLOB_FIELDS_SIZE] = [(); core::mem::size_of::<RuntimeDotBlobFields>()];
const _: [(); DOT_BLOB_SIZE] = [(); core::mem::size_of::<RuntimeDotBlob>()];

#[derive(Clone, Copy)]
struct UnlockContext {
    challenge: [u8; AUTH_CMD_NONCE_LEN],
    lak_hash: [u8; DOT_KEY_HASH_SIZE],
    fuse_count: u32,
}

static UNLOCK_CONTEXT: BlockingMutex<CriticalSectionRawMutex, RefCell<Option<UnlockContext>>> =
    BlockingMutex::new(RefCell::new(None));

static DOT_TRANSACTION_BUSY: AtomicBool = AtomicBool::new(false);

struct DotTransactionGuard;

impl DotTransactionGuard {
    fn acquire() -> CaliptraCmdResult<Self> {
        DOT_TRANSACTION_BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| CaliptraCompletionCode::ResourceUnavailable)
    }
}

impl Drop for DotTransactionGuard {
    fn drop(&mut self) {
        DOT_TRANSACTION_BUSY.store(false, Ordering::Release);
    }
}

struct SegmentedPayloadStream<'a, const N: usize> {
    segments: [&'a [u8]; N],
    segment: usize,
    offset: usize,
}

impl<'a, const N: usize> SegmentedPayloadStream<'a, N> {
    fn new(segments: [&'a [u8]; N]) -> Self {
        Self {
            segments,
            segment: 0,
            offset: 0,
        }
    }
    fn read_into(&mut self, buffer: &mut [u8]) -> usize {
        let mut written = 0;
        while written < buffer.len() && self.segment < N {
            let remaining = &self.segments[self.segment][self.offset..];
            let count = remaining.len().min(buffer.len() - written);
            buffer[written..written + count].copy_from_slice(&remaining[..count]);
            written += count;
            self.offset += count;

            if self.offset == self.segments[self.segment].len() {
                self.segment += 1;
                self.offset = 0;
            }
        }
        written
    }
}

#[async_trait(?Send)]
impl<const N: usize> PayloadStream for SegmentedPayloadStream<'_, N> {
    fn size(&self) -> usize {
        self.segments.iter().map(|segment| segment.len()).sum()
    }

    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ErrorCode> {
        Ok(self.read_into(buffer))
    }
}

fn mailbox_checksum_segments<const N: usize>(command: u32, segments: [&[u8]; N]) -> u32 {
    let sum = command
        .to_le_bytes()
        .iter()
        .chain(segments.iter().flat_map(|segment| segment.iter()))
        .fold(0u32, |sum, byte| sum.wrapping_add(*byte as u32));
    0u32.wrapping_sub(sum)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    #[test]
    fn segmented_payload_preserves_wire_order_and_checksum() {
        let command = 0x4d4c_4453;
        let segments: [&[u8]; 4] = [&[1, 2, 3], &[], &[4, 5], &[6]];
        let mut stream = SegmentedPayloadStream::new(segments);
        let mut actual = Vec::new();
        let mut chunk = [0u8; 2];

        loop {
            let len = stream.read_into(&mut chunk);
            if len == 0 {
                break;
            }
            actual.extend_from_slice(&chunk[..len]);
        }

        assert_eq!(actual, [1, 2, 3, 4, 5, 6]);
        let mut request = Vec::from([0u8; 4]);
        request.extend_from_slice(&actual);
        assert_eq!(
            mailbox_checksum_segments(command, segments),
            caliptra_api::calc_checksum(command, &request)
        );
    }
}

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

    let mut mldsa_digest = [0u8; 64];
    hash_all(
        alloc,
        HashAlgo::Sha512,
        pre_image.as_slice(),
        &mut mldsa_digest,
    )
    .await
    .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    verify_hybrid_message_parts(
        alloc,
        pre_image.as_slice(),
        &mldsa_digest,
        ecc_pub_x,
        ecc_pub_y,
        mldsa_pub,
        sig,
    )
    .await
}

async fn verify_hybrid_message_parts<A: ApiAlloc>(
    alloc: &A,
    ecc_message: &[u8],
    mldsa_message: &[u8],
    ecc_pub_x: &[u8; 48],
    ecc_pub_y: &[u8; 48],
    mldsa_pub: &[u8; DOT_MLDSA_PUBLIC_KEY_SIZE],
    sig: &HybridSignature,
) -> CaliptraCmdResult<()> {
    let mut hash = [0u8; 48];
    hash_all(alloc, HashAlgo::Sha384, ecc_message, &mut hash)
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

    let mut mldsa_resp = MailboxRespHeader::default();
    let mldsa_resp_bytes = mldsa_resp.as_mut_bytes();
    let cmd_mldsa_verify: u32 = caliptra_api::mailbox::CommandId::MLDSA87_SIGNATURE_VERIFY.into();
    let message_size = (mldsa_message.len() as u32).to_le_bytes();
    let segments = [
        mldsa_pub.as_slice(),
        sig.mldsa_sig.as_slice(),
        message_size.as_slice(),
        mldsa_message,
    ];
    let checksum = mailbox_checksum_segments(cmd_mldsa_verify, segments);
    let mut payload = SegmentedPayloadStream::new(segments);

    Mailbox::<DefaultSyscalls>::new()
        .execute_with_payload_stream(
            cmd_mldsa_verify,
            Some(&checksum.to_le_bytes()),
            &mut payload,
            mldsa_resp_bytes,
        )
        .await
        .map_err(|_| CaliptraCompletionCode::AccessDenied)?;

    Ok(())
}

async fn verify_hybrid_message<A: ApiAlloc>(
    alloc: &A,
    message: &[u8],
    ecc_pub_x: &[u8; 48],
    ecc_pub_y: &[u8; 48],
    mldsa_pub: &[u8; DOT_MLDSA_PUBLIC_KEY_SIZE],
    sig: &HybridSignature,
) -> CaliptraCmdResult<()> {
    verify_hybrid_message_parts(alloc, message, message, ecc_pub_x, ecc_pub_y, mldsa_pub, sig).await
}

async fn dot_lak_hash<A: ApiAlloc>(
    alloc: &A,
    ecc_pub_x: &[u8; 48],
    ecc_pub_y: &[u8; 48],
    mldsa_pub: &[u8; DOT_MLDSA_PUBLIC_KEY_SIZE],
) -> CaliptraCmdResult<[u8; DOT_KEY_HASH_SIZE]> {
    let mut ecc_key = [0u8; 96];
    for (dst, src) in ecc_key[..48]
        .chunks_exact_mut(4)
        .zip(ecc_pub_x.chunks_exact(4))
    {
        dst.copy_from_slice(src);
        dst.reverse();
    }
    for (dst, src) in ecc_key[48..]
        .chunks_exact_mut(4)
        .zip(ecc_pub_y.chunks_exact(4))
    {
        dst.copy_from_slice(src);
        dst.reverse();
    }
    let context = alloc
        .alloc(SHA_CONTEXT_SIZE)
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;
    let mut state = sha_init(alloc, context, HashAlgo::Sha384, &ecc_key)
        .await
        .map_err(map_mcu_err)?;
    sha_update(alloc, &mut state, mldsa_pub)
        .await
        .map_err(map_mcu_err)?;
    let mut hash = [0u8; DOT_KEY_HASH_SIZE];
    sha_finish(alloc, &mut state, &mut hash)
        .await
        .map_err(map_mcu_err)?;
    Ok(hash)
}

fn read_dot_fuse_count() -> CaliptraCmdResult<u32> {
    let otp = Otp::<DefaultSyscalls>::new();
    let initialized = otp
        .read_raw((fuses::DOT_INITIALIZED.byte_offset / 4) as u32, 0)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if initialized & 0x7 == 0 {
        return Err(CaliptraCompletionCode::InvalidState);
    }

    let mut burned = 0u32;
    for index in 0..(fuses::DOT_FUSE_ARRAY.byte_size / 4) {
        burned += otp
            .read_raw((fuses::DOT_FUSE_ARRAY.byte_offset / 4) as u32, index as u32)
            .map_err(|_| CaliptraCompletionCode::OperationFailed)?
            .count_ones();
    }
    Ok(burned)
}

fn dot_derivation_info(derivation_value: u32) -> CaliptraCmdResult<[u8; 32]> {
    let derivation_value =
        u16::try_from(derivation_value).map_err(|_| CaliptraCompletionCode::InvalidState)?;
    let mut info = [0u8; 32];
    info[..DOT_LABEL.len()].copy_from_slice(DOT_LABEL);
    info[DOT_LABEL.len()..DOT_LABEL.len() + 2].copy_from_slice(&derivation_value.to_le_bytes());
    Ok(info)
}

async fn seal_dot_blob<A: ApiAlloc>(
    alloc: &A,
    derivation_value: u32,
    cak: [u8; DOT_KEY_HASH_SIZE],
    lak_hash: [u8; DOT_KEY_HASH_SIZE],
) -> CaliptraCmdResult<RuntimeDotBlob> {
    let info = dot_derivation_info(derivation_value)?;
    let key = derive_stable_key(StableKeyType::IDevId, &info)
        .await
        .map_err(map_mcu_err)?;
    let fields = RuntimeDotBlobFields {
        version: DOT_BLOB_VERSION,
        cak,
        lak_pub: lak_hash,
        unlock_method: DOT_UNLOCK_METHOD_CHALLENGE_RESPONSE,
        reserved: [0; 3],
    };
    let mut hmac = [0u8; DOT_HMAC_SIZE];
    cm_hmac_sha512(alloc, &key, fields.as_bytes(), &mut hmac)
        .await
        .map_err(map_mcu_err)?;
    Ok(RuntimeDotBlob { fields, hmac })
}

async fn write_and_verify_dot_blob(blob: &RuntimeDotBlob) -> CaliptraCmdResult<()> {
    let flash = SpiFlash::<DefaultSyscalls>::new(caliptra_mcu_config::DOT_BLOB_STORE_DRIVER_NUM);
    flash
        .exists()
        .map_err(|_| CaliptraCompletionCode::UnsupportedOperation)?;
    if (flash
        .get_capacity()
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?
        .0 as usize)
        < DOT_BLOB_SIZE
    {
        return Err(CaliptraCompletionCode::InsufficientResources);
    }
    flash
        .write(0, DOT_BLOB_SIZE, blob.as_bytes())
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let mut readback = [0u8; DOT_BLOB_SIZE];
    flash
        .read(0, DOT_BLOB_SIZE, &mut readback)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if !constant_time_eq::constant_time_eq(&readback, blob.as_bytes()) {
        return Err(CaliptraCompletionCode::OperationFailed);
    }
    Ok(())
}

pub fn provision_vendor_pk_hash(slot: u32, hash: &[u8; 48]) -> CaliptraCmdResult<()> {
    Otp::<DefaultSyscalls>::new()
        .provision_vendor_pk_hash(slot, hash)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)
}

pub fn provision_owner_pk_hash(hash: &[u8; 48]) -> CaliptraCmdResult<()> {
    Otp::<DefaultSyscalls>::new()
        .provision_owner_pk_hash(hash)
        .map_err(|error| match error {
            ErrorCode::Invalid => CaliptraCompletionCode::InvalidParameter,
            _ => CaliptraCompletionCode::OperationFailed,
        })
}

pub fn fuse_lock_partition(partition: u32) -> CaliptraCmdResult<()> {
    Otp::<DefaultSyscalls>::new()
        .lock_partition(partition)
        .map_err(|error| match error {
            ErrorCode::Invalid => CaliptraCompletionCode::InvalidParameter,
            _ => CaliptraCompletionCode::OperationFailed,
        })
}

pub async fn increase_caliptra_min_svn<A: ApiAlloc>(alloc: &A, svn: u32) -> CaliptraCmdResult<()> {
    if svn == 0 || svn > 128 {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let caliptra_fw_info = fw_info(alloc)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if svn > caliptra_fw_info.fw_svn {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let otp = Otp::<DefaultSyscalls>::new();
    let mut current_fuses = [0u32; 4];
    for (i, fuse) in current_fuses.iter_mut().enumerate() {
        *fuse = otp
            .read(otp::reg::CALIPTRA_FW_SVN, i as u32)
            .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    }

    let fuse = u128::from_le_bytes(current_fuses.as_bytes().try_into().unwrap());
    let fused_min_svn = 128 - fuse.leading_zeros();
    if svn < fused_min_svn {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }
    if svn == fused_min_svn {
        return Ok(());
    }

    let new_fuse_svn = if svn == 128 {
        u128::MAX
    } else {
        !(u128::MAX << svn)
    };
    for (i, (current, new_bytes)) in current_fuses
        .iter()
        .zip(new_fuse_svn.as_bytes().chunks_exact(4))
        .enumerate()
    {
        let new_svn_word = u32::from_le_bytes(new_bytes.try_into().unwrap());
        if *current != new_svn_word {
            otp.write(otp::reg::CALIPTRA_FW_SVN, i as u32, new_svn_word)
                .map_err(|_| CaliptraCompletionCode::InvalidParameter)?;
        }
    }
    Ok(())
}

async fn read_and_verify_dot_blob<A: ApiAlloc>(
    alloc: &A,
    derivation_value: u32,
) -> CaliptraCmdResult<RuntimeDotBlob> {
    if derivation_value & 1 == 0 {
        return Err(CaliptraCompletionCode::InvalidState);
    }
    let flash = SpiFlash::<DefaultSyscalls>::new(caliptra_mcu_config::DOT_BLOB_STORE_DRIVER_NUM);
    let mut bytes = [0u8; DOT_BLOB_SIZE];
    flash
        .read(0, DOT_BLOB_SIZE, &mut bytes)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let blob = RuntimeDotBlob::read_from_bytes(&bytes)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if blob.fields.version != DOT_BLOB_VERSION {
        return Err(CaliptraCompletionCode::InvalidState);
    }
    let info = dot_derivation_info(derivation_value)?;
    let key = derive_stable_key(StableKeyType::IDevId, &info)
        .await
        .map_err(map_mcu_err)?;
    let mut expected = [0u8; DOT_HMAC_SIZE];
    cm_hmac_sha512(alloc, &key, blob.fields.as_bytes(), &mut expected)
        .await
        .map_err(map_mcu_err)?;
    if !constant_time_eq::constant_time_eq(&expected, &blob.hmac) {
        return Err(CaliptraCompletionCode::AccessDenied);
    }
    Ok(blob)
}

fn burn_next_dot_fuse(current_fuse_count: u32) -> CaliptraCmdResult<()> {
    let word_addr = (fuses::DOT_FUSE_ARRAY.byte_offset / 4) as u32 + current_fuse_count / 32;
    let bit_mask = 1u32 << (current_fuse_count % 32);
    let otp = Otp::<DefaultSyscalls>::new();
    let current_word = otp
        .read_raw(word_addr, 0)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if current_word & bit_mask != 0 {
        return Err(CaliptraCompletionCode::InvalidState);
    }
    otp.write_raw(word_addr, bit_mask, bit_mask)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if read_dot_fuse_count()? != current_fuse_count + 1 {
        return Err(CaliptraCompletionCode::OperationFailed);
    }
    caliptra_mcu_romtime::println!("[mcu-rt-dot] DOT fuse committed");
    Ok(())
}

async fn commit_dot_transition<A: ApiAlloc>(
    alloc: &A,
    current_fuse_count: u32,
    derivation_value: u32,
    cak: [u8; DOT_KEY_HASH_SIZE],
    lak_hash: [u8; DOT_KEY_HASH_SIZE],
) -> CaliptraCmdResult<()> {
    let blob = seal_dot_blob(alloc, derivation_value, cak, lak_hash)
        .await
        .map_err(|error| {
            caliptra_mcu_romtime::println!("[mcu-rt-dot] Blob sealing failed: {}", error as u8);
            error
        })?;
    write_and_verify_dot_blob(&blob).await.map_err(|error| {
        caliptra_mcu_romtime::println!("[mcu-rt-dot] Blob write failed: {}", error as u8);
        error
    })?;
    burn_next_dot_fuse(current_fuse_count).map_err(|error| {
        caliptra_mcu_romtime::println!("[mcu-rt-dot] Fuse burn failed: {}", error as u8);
        error
    })
}

pub async fn dot_lock<A: ApiAlloc>(alloc: &A, request: &DotLockPayload) -> CaliptraCmdResult<()> {
    let _guard = DotTransactionGuard::acquire()?;
    dot_lock_impl(alloc, request).await
}

async fn dot_lock_impl<A: ApiAlloc>(alloc: &A, request: &DotLockPayload) -> CaliptraCmdResult<()> {
    if request.cak.iter().all(|byte| *byte == 0) {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    if request.lak_hash.iter().all(|byte| *byte == 0) {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let current_fuse_count = read_dot_fuse_count()?;
    if current_fuse_count & 1 != 0 || current_fuse_count >= 256 {
        return Err(CaliptraCompletionCode::InvalidState);
    }

    commit_dot_transition(
        alloc,
        current_fuse_count,
        current_fuse_count + 1,
        request.cak,
        request.lak_hash,
    )
    .await
}

pub async fn dot_disable<A: ApiAlloc>(
    alloc: &A,
    request: &DotDisablePayload,
) -> CaliptraCmdResult<()> {
    let _guard = DotTransactionGuard::acquire()?;
    if request.lak_hash.iter().all(|byte| *byte == 0) {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let current_fuse_count = read_dot_fuse_count()?;
    if current_fuse_count & 1 != 0 || current_fuse_count >= 256 {
        return Err(CaliptraCompletionCode::InvalidState);
    }

    commit_dot_transition(
        alloc,
        current_fuse_count,
        current_fuse_count + 1,
        [0; DOT_KEY_HASH_SIZE],
        request.lak_hash,
    )
    .await
}

pub async fn dot_unlock_challenge<A: ApiAlloc>(
    alloc: &A,
) -> CaliptraCmdResult<[u8; AUTH_CMD_NONCE_LEN]> {
    let _guard = DotTransactionGuard::acquire()?;
    if UNLOCK_CONTEXT.lock(|state| state.borrow().is_some()) {
        return Err(CaliptraCompletionCode::ResourceUnavailable);
    }
    let current_fuse_count = read_dot_fuse_count()?;
    if current_fuse_count & 1 == 0 {
        return Err(CaliptraCompletionCode::InvalidState);
    }
    let blob = read_and_verify_dot_blob(alloc, current_fuse_count).await?;
    if blob.fields.lak_pub.iter().all(|byte| *byte == 0) {
        return Err(CaliptraCompletionCode::InvalidState);
    }

    let mut challenge = [0u8; AUTH_CMD_NONCE_LEN];
    rng_generate(alloc, &mut challenge)
        .await
        .map_err(map_mcu_err)?;
    UNLOCK_CONTEXT.lock(|state| {
        *state.borrow_mut() = Some(UnlockContext {
            challenge,
            lak_hash: blob.fields.lak_pub,
            fuse_count: current_fuse_count,
        });
    });
    Ok(challenge)
}

pub async fn dot_unlock<A: ApiAlloc>(
    alloc: &A,
    request: &DotUnlockPayload,
) -> CaliptraCmdResult<()> {
    let _guard = DotTransactionGuard::acquire()?;
    let context = UNLOCK_CONTEXT
        .lock(|state| *state.borrow())
        .ok_or(CaliptraCompletionCode::InvalidState)?;
    let current_fuse_count = read_dot_fuse_count()?;
    if current_fuse_count != context.fuse_count || current_fuse_count & 1 == 0 {
        return Err(CaliptraCompletionCode::InvalidState);
    }

    let lak_hash = dot_lak_hash(
        alloc,
        &request.lak_ecc_pub_x,
        &request.lak_ecc_pub_y,
        &request.lak_mldsa_pub,
    )
    .await?;
    if !constant_time_eq::constant_time_eq(&lak_hash, &context.lak_hash) {
        return Err(CaliptraCompletionCode::AccessDenied);
    }

    let mut transcript = [0u8; 4 + AUTH_CMD_NONCE_LEN];
    transcript[..4].copy_from_slice(&CommandId::MC_DOT_UNLOCK.0.to_be_bytes());
    transcript[4..].copy_from_slice(&context.challenge);
    verify_hybrid_message(
        alloc,
        &transcript,
        &request.lak_ecc_pub_x,
        &request.lak_ecc_pub_y,
        &request.lak_mldsa_pub,
        &request.signature,
    )
    .await?;
    commit_dot_transition(
        alloc,
        current_fuse_count,
        current_fuse_count + 2,
        [0; DOT_KEY_HASH_SIZE],
        context.lak_hash,
    )
    .await?;
    UNLOCK_CONTEXT.lock(|state| *state.borrow_mut() = None);
    Ok(())
}

pub async fn revoke_vendor_pub_key<A: ApiAlloc>(
    alloc: &A,
    vendor_pk_hash_slot: u32,
    key_type: u32,
    key_index: u32,
) -> CaliptraCmdResult<()> {
    let key_type = RevokeVendorPubKeyType::try_from(key_type)
        .map_err(|_| CaliptraCompletionCode::InvalidParameter)?;
    let otp = Otp::<DefaultSyscalls>::new();
    if !otp.valid_vendor_pk_hash_slot(vendor_pk_hash_slot) {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }
    let pk_hash_from_slot = otp
        .read_vendor_pk_hash(vendor_pk_hash_slot)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if pk_hash_from_slot.iter().all(|byte| *byte == 0) {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let caliptra_info = fw_info(alloc)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let booted_pk_hash = caliptra::Caliptra::<DefaultSyscalls>::new()
        .read_vendor_pk_hash()
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if booted_pk_hash == pk_hash_from_slot {
        const FW_VERIFICATION_PQC_TYPE_MLDSA: u32 = 1;
        const FW_VERIFICATION_PQC_TYPE_LMS: u32 = 3;
        let same_key = match (key_type, caliptra_info.image_manifest_pqc_type) {
            (RevokeVendorPubKeyType::Ecdsa384, _) => {
                key_index == caliptra_info.vendor_ecc384_pub_key_index
            }
            (RevokeVendorPubKeyType::Lms, FW_VERIFICATION_PQC_TYPE_LMS)
            | (RevokeVendorPubKeyType::Mldsa87, FW_VERIFICATION_PQC_TYPE_MLDSA) => {
                key_index == caliptra_info.vendor_pqc_pub_key_index
            }
            _ => false,
        };
        if same_key {
            return Err(CaliptraCompletionCode::InvalidParameter);
        }
    }

    otp.revoke_vendor_pub_key(vendor_pk_hash_slot, key_type, key_index)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)
}

pub fn revoke_vendor_pk_hash(vendor_pk_hash_slot: u32) -> CaliptraCmdResult<()> {
    const MAX_VENDOR_PK_HASH_SLOTS: u32 = 16;
    if vendor_pk_hash_slot >= MAX_VENDOR_PK_HASH_SLOTS {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let otp = Otp::<DefaultSyscalls>::new();
    // A cleared validity bit is the persistent indication that this slot was
    // already revoked. Preserve the mailbox policy's idempotent behavior
    // without attempting to read a now-invalid slot.
    if !otp.valid_vendor_pk_hash_slot(vendor_pk_hash_slot) {
        return Ok(());
    }

    let booted_pk_hash = caliptra::Caliptra::<DefaultSyscalls>::new()
        .read_vendor_pk_hash()
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let pk_hash_from_slot = otp
        .read_vendor_pk_hash(vendor_pk_hash_slot)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if booted_pk_hash == pk_hash_from_slot {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    otp.revoke_vendor_pk_hash(vendor_pk_hash_slot)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)
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
