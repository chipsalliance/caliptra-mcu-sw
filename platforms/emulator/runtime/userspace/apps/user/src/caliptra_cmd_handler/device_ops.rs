// Licensed under the Apache-2.0 license

use arrayvec::ArrayVec;
use caliptra_api::mailbox::{EcdsaVerifyReq, MailboxReqHeader, MailboxRespHeader, MldsaVerifyReq};
use caliptra_mcu_common_commands::{
    CaliptraCmdResult, CaliptraCompletionCode, DEBUG_UNLOCK_CHALLENGE_SIZE,
    DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash;
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError};
use caliptra_mcu_libsyscall_caliptra::otp::Otp;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_mbox_common::messages::{
    CommandId, DotDisablePayload, DotLockPayload, DotUnlockPayload, HybridSignature,
    AUTH_CMD_NONCE_LEN, DOT_KEY_HASH_SIZE, DOT_MLDSA_PUBLIC_KEY_SIZE,
};
use caliptra_mcu_registers_generated::fuses;
use core::cell::RefCell;
use embassy_sync::blocking_mutex::{raw::CriticalSectionRawMutex, Mutex as BlockingMutex};
use embassy_sync::mutex::Mutex as AsyncMutex;
use mcu_caliptra_api_lite::{
    cm_hmac_sha512, derive_stable_key, fe_prog, get_attested_csr_ecc384, get_attested_csr_mldsa87,
    get_idev_csr_ecc384, request_debug_unlock_challenge, rng_generate, sha_finish, sha_init,
    sha_update, ApiAlloc, HashAlgo, McuErrorCode, StableKeyType,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
    SHA_CONTEXT_SIZE,
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
// SAFETY: MldsaVerifyReq derives FromBytes, so all-zeros is a valid representation.
static MLDSA_VERIFY_REQ: AsyncMutex<
    CriticalSectionRawMutex,
    core::mem::MaybeUninit<MldsaVerifyReq>,
> = AsyncMutex::new(core::mem::MaybeUninit::zeroed());

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
pub async fn verify_authorized_signatures(
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
    let mut pk_hash = [0u8; 48];
    let mut anchor_ctx = HashContext::new();
    anchor_ctx
        .init(HashAlgoType::SHA384, Some(&ecc_pub_x[..]))
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    anchor_ctx
        .update(&ecc_pub_y[..])
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    anchor_ctx
        .update(&mldsa_pub[..])
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    anchor_ctx
        .finalize(&mut pk_hash)
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
    HashContext::hash_all(
        HashAlgoType::SHA512,
        pre_image.as_slice(),
        &mut mldsa_digest,
    )
    .await
    .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    verify_hybrid_message_parts(
        pre_image.as_slice(),
        &mldsa_digest,
        ecc_pub_x,
        ecc_pub_y,
        mldsa_pub,
        sig,
    )
    .await
}

async fn verify_hybrid_message(
    message: &[u8],
    ecc_pub_x: &[u8; 48],
    ecc_pub_y: &[u8; 48],
    mldsa_pub: &[u8; DOT_MLDSA_PUBLIC_KEY_SIZE],
    sig: &HybridSignature,
) -> CaliptraCmdResult<()> {
    verify_hybrid_message_parts(message, message, ecc_pub_x, ecc_pub_y, mldsa_pub, sig).await
}

async fn verify_hybrid_message_parts(
    ecc_message: &[u8],
    mldsa_message: &[u8],
    ecc_pub_x: &[u8; 48],
    ecc_pub_y: &[u8; 48],
    mldsa_pub: &[u8; DOT_MLDSA_PUBLIC_KEY_SIZE],
    sig: &HybridSignature,
) -> CaliptraCmdResult<()> {
    let mailbox = Mailbox::new();

    let mut hash = [0u8; 48];
    HashContext::hash_all(HashAlgoType::SHA384, ecc_message, &mut hash)
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

    execute_mailbox_cmd(&mailbox, cmd_ecdsa_verify, ecc_req_bytes, ecc_resp_bytes)
        .await
        .map_err(|_| CaliptraCompletionCode::AccessDenied)?;

    let mut guard = MLDSA_VERIFY_REQ.lock().await;
    // SAFETY: MldsaVerifyReq derives FromBytes — all-zeros (from the static
    // initializer) and any byte pattern we write are valid representations.
    let req: &mut MldsaVerifyReq = unsafe { guard.assume_init_mut() };
    if mldsa_message.len() > req.message.len() {
        return Err(CaliptraCompletionCode::InsufficientResources);
    }
    req.hdr = MailboxReqHeader::default();
    req.pub_key = *mldsa_pub;
    req.signature = sig.mldsa_sig;
    req.message_size = mldsa_message.len() as u32;
    req.message = [0u8; caliptra_api::mailbox::MAX_CMB_DATA_SIZE];
    req.message[..mldsa_message.len()].copy_from_slice(mldsa_message);

    let mldsa_req_bytes = req
        .as_bytes_partial_mut()
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

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
    let blob = seal_dot_blob(alloc, derivation_value, cak, lak_hash).await?;
    write_and_verify_dot_blob(&blob).await?;
    burn_next_dot_fuse(current_fuse_count)
}

pub async fn dot_lock<A: ApiAlloc>(alloc: &A, request: &DotLockPayload) -> CaliptraCmdResult<()> {
    let _guard = DotTransactionGuard::acquire()?;
    dot_lock_impl(alloc, request).await
}

async fn dot_lock_impl<A: ApiAlloc>(alloc: &A, request: &DotLockPayload) -> CaliptraCmdResult<()> {
    if request.cak.iter().all(|byte| *byte == 0) {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let lak_hash = dot_lak_hash(
        alloc,
        &request.lak_ecc_pub_x,
        &request.lak_ecc_pub_y,
        &request.lak_mldsa_pub,
    )
    .await?;
    if lak_hash.iter().all(|byte| *byte == 0) {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let mut transcript = [0u8; 4 + 2 * DOT_KEY_HASH_SIZE];
    transcript[..4].copy_from_slice(&CommandId::MC_DOT_LOCK.0.to_be_bytes());
    transcript[4..4 + DOT_KEY_HASH_SIZE].copy_from_slice(&request.cak);
    transcript[4 + DOT_KEY_HASH_SIZE..].copy_from_slice(&lak_hash);
    verify_hybrid_message(
        &transcript,
        &request.lak_ecc_pub_x,
        &request.lak_ecc_pub_y,
        &request.lak_mldsa_pub,
        &request.signature,
    )
    .await?;

    let current_fuse_count = read_dot_fuse_count()?;
    if current_fuse_count & 1 != 0 || current_fuse_count >= 256 {
        return Err(CaliptraCompletionCode::InvalidState);
    }

    commit_dot_transition(
        alloc,
        current_fuse_count,
        current_fuse_count + 1,
        request.cak,
        lak_hash,
    )
    .await
}

pub async fn dot_disable<A: ApiAlloc>(
    alloc: &A,
    request: &DotDisablePayload,
) -> CaliptraCmdResult<()> {
    let _guard = DotTransactionGuard::acquire()?;
    let lak_hash = dot_lak_hash(
        alloc,
        &request.lak_ecc_pub_x,
        &request.lak_ecc_pub_y,
        &request.lak_mldsa_pub,
    )
    .await?;
    if lak_hash.iter().all(|byte| *byte == 0) {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let mut transcript = [0u8; 4 + DOT_KEY_HASH_SIZE];
    transcript[..4].copy_from_slice(&CommandId::MC_DOT_DISABLE.0.to_be_bytes());
    transcript[4..].copy_from_slice(&lak_hash);
    verify_hybrid_message(
        &transcript,
        &request.lak_ecc_pub_x,
        &request.lak_ecc_pub_y,
        &request.lak_mldsa_pub,
        &request.signature,
    )
    .await?;

    let current_fuse_count = read_dot_fuse_count()?;
    if current_fuse_count & 1 != 0 || current_fuse_count >= 256 {
        return Err(CaliptraCompletionCode::InvalidState);
    }

    commit_dot_transition(
        alloc,
        current_fuse_count,
        current_fuse_count + 1,
        [0; DOT_KEY_HASH_SIZE],
        lak_hash,
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
        [0; DOT_KEY_HASH_SIZE],
    )
    .await?;
    UNLOCK_CONTEXT.lock(|state| *state.borrow_mut() = None);
    Ok(())
}

pub async fn dot_get_backup_blob<A: ApiAlloc>(
    alloc: &A,
    output: &mut [u8; DOT_BLOB_SIZE],
) -> CaliptraCmdResult<()> {
    let _guard = DotTransactionGuard::acquire()?;
    let current_fuse_count = read_dot_fuse_count()?;
    if current_fuse_count & 1 == 0 {
        return Err(CaliptraCompletionCode::InvalidState);
    }

    let blob = read_and_verify_dot_blob(alloc, current_fuse_count).await?;
    output.copy_from_slice(blob.as_bytes());
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
