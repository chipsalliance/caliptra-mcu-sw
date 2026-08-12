// Licensed under the Apache-2.0 license

use caliptra_mcu_libsyscall_caliptra::caliptra::Caliptra;
use caliptra_mcu_libsyscall_caliptra::otp::{self, Otp, RevokeVendorPubKeyType};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_mbox_common::messages::{
    CommandId, FuseIncreaseCaliptraMinSvnReqPayload, FuseLockPartitionReqPayload,
    FuseReadReqPayload, FuseReadRespPayload, FuseRevokeVendorPkHashReqPayload,
    FuseRevokeVendorPubKeyReqPayload, FuseWriteReqPayload, McuFeProgReqPayload,
    ProvisionOwnerPkHashReqPayload, ProvisionVendorPkHashReqPayload, MAX_FUSE_DATA_SIZE,
};
use caliptra_mcu_otp_fuse::{fuse_read_dai_params, PartitionId};
use mcu_caliptra_api::{fe_prog, fw_info, ApiAlloc, McuErrorCode};
use zerocopy::{FromBytes, IntoBytes};

use crate::{CaliptraCmdResult, CaliptraCompletionCode, CommandAuthorizer};

pub struct AuthorizedCmdExecutor;

impl AuthorizedCmdExecutor {
    /// Authorizes and executes an authorized command payload.
    ///
    /// `authorizer` verifies the nonce and signatures, unpacking the command payload.
    /// `req` is expected to have the canonical authorized message layout: `[cmd_payload][AuthorizationBlock]`.
    /// `resp_buf` is the buffer where any response body is written.
    /// Returns the number of bytes written to `resp_buf`.
    pub async fn execute<A: ApiAlloc, Auth: CommandAuthorizer>(
        authorizer: &mut Auth,
        alloc: &A,
        cmd_id: CommandId,
        req: &[u8],
        resp_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let payload = authorizer
            .is_authorized(alloc, cmd_id, req)
            .await
            .map_err(|_| CaliptraCompletionCode::AccessDenied)?;
        match cmd_id {
            CommandId::MC_PROVISION_VENDOR_PK_HASH => {
                handle_provision_vendor_pk_hash(payload).await
            }
            CommandId::MC_PROVISION_OWNER_PK_HASH => handle_provision_owner_pk_hash(payload).await,
            CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN => {
                handle_increase_caliptra_min_svn(alloc, payload).await
            }
            CommandId::MC_FE_PROG => handle_fe_prog(alloc, payload).await,
            CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY => {
                handle_revoke_vendor_pub_key(alloc, payload).await
            }
            CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH => handle_revoke_vendor_pk_hash(payload).await,
            CommandId::MC_FUSE_READ => handle_fuse_read(payload, resp_buf).await,
            CommandId::MC_FUSE_WRITE => handle_fuse_write(payload).await,
            CommandId::MC_FUSE_LOCK_PARTITION => handle_fuse_lock_partition(payload).await,
            _ => Err(CaliptraCompletionCode::UnsupportedOperation),
        }
    }
}

impl From<McuErrorCode> for CaliptraCompletionCode {
    fn from(e: McuErrorCode) -> Self {
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
}

async fn handle_fuse_read(payload: &[u8], resp_buf: &mut [u8]) -> CaliptraCmdResult<usize> {
    // Decode the request
    let req = FuseReadReqPayload::ref_from_bytes(payload)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;

    let (resp, _) = FuseReadRespPayload::mut_from_prefix(resp_buf)
        .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;
    *resp = FuseReadRespPayload::default();

    let params = fuse_read_dai_params(req.partition, req.entry, MAX_FUSE_DATA_SIZE / 4)
        .map_err(|_| CaliptraCompletionCode::InvalidParameter)?;

    let otp: Otp<DefaultSyscalls> = Otp::new();

    // Create a iterator over the words in the response that yields at most `params.words_to_read`
    // (which is less or equal to the words in resp.data).
    let words = resp.data.chunks_exact_mut(4).take(params.words_to_read);
    for (i, word) in words.enumerate() {
        let data = otp
            .read_raw(params.base_word_addr as u32, i as u32)
            .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
        let bytes = data.to_ne_bytes();
        word.copy_from_slice(&bytes);
    }

    resp.length_bits = params.valid_bits;

    Ok(core::mem::size_of::<FuseReadRespPayload>())
}

async fn handle_fuse_write(payload: &[u8]) -> CaliptraCmdResult<usize> {
    // Decode the request
    let req = FuseWriteReqPayload::ref_from_bytes(payload)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;

    let otp: Otp<DefaultSyscalls> = Otp::new();
    otp.write_raw(req.word_addr, req.data, req.mask)
        .map_err(|e| match e {
            caliptra_mcu_libtock_platform::ErrorCode::Invalid => {
                CaliptraCompletionCode::InvalidParameter
            }
            _ => CaliptraCompletionCode::OperationFailed,
        })?;

    Ok(0)
}

async fn handle_fuse_lock_partition(payload: &[u8]) -> CaliptraCmdResult<usize> {
    // Decode the request
    let req = FuseLockPartitionReqPayload::ref_from_bytes(payload)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;

    PartitionId::try_from(req.partition).map_err(|_| CaliptraCompletionCode::InvalidParameter)?;

    let otp: Otp<DefaultSyscalls> = Otp::new();
    otp.lock_partition(req.partition)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    Ok(0)
}

async fn handle_provision_vendor_pk_hash(payload: &[u8]) -> CaliptraCmdResult<usize> {
    let req = ProvisionVendorPkHashReqPayload::ref_from_bytes(payload)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;

    let otp: Otp<DefaultSyscalls> = Otp::new();
    otp.provision_vendor_pk_hash(req.slot, &req.hash)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    Ok(0)
}

async fn handle_provision_owner_pk_hash(payload: &[u8]) -> CaliptraCmdResult<usize> {
    let req = ProvisionOwnerPkHashReqPayload::ref_from_bytes(payload)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;

    Otp::<DefaultSyscalls>::new()
        .provision_owner_pk_hash(&req.hash)
        .map_err(|error| match error {
            ErrorCode::Invalid => CaliptraCompletionCode::InvalidParameter,
            _ => CaliptraCompletionCode::OperationFailed,
        })?;

    Ok(0)
}

async fn handle_increase_caliptra_min_svn<A: ApiAlloc>(
    alloc: &A,
    payload: &[u8],
) -> CaliptraCmdResult<usize> {
    // Decode the request
    let req = FuseIncreaseCaliptraMinSvnReqPayload::ref_from_bytes(payload)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
    let FuseIncreaseCaliptraMinSvnReqPayload { svn, flags } = *req;

    if flags != 0 {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    // Check the request has a valid SVN value
    if svn == 0 || svn > 128 {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let caliptra_fw_info = fw_info(alloc).await?;

    // Ensure the requested SVN will allow current Caliptra firmware to run
    if svn > caliptra_fw_info.fw_svn {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    // Get the minimum SVN set in fuses
    let otp = Otp::<DefaultSyscalls>::new();
    let mut current_fuses = [0u32; 4];
    for (i, fuse) in current_fuses.iter_mut().enumerate() {
        *fuse = otp
            .read(otp::reg::CALIPTRA_FW_SVN, i as u32)
            .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    }

    // Convert the fuses to the SVN value
    let fuse = u128::from_le_bytes(current_fuses.as_bytes().try_into().unwrap());
    let fused_min_svn = 128 - fuse.leading_zeros();

    // Ensure we are not trying to decrease the SVN
    if svn < fused_min_svn {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    // We are done, if the fuses already match the requested SVN.
    if svn == fused_min_svn {
        return Ok(0);
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
    Ok(0)
}

async fn handle_fe_prog<A: ApiAlloc>(alloc: &A, payload: &[u8]) -> CaliptraCmdResult<usize> {
    // Decode the request
    let req = McuFeProgReqPayload::ref_from_bytes(payload)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;

    fe_prog(alloc, req.partition).await?;
    Ok(0)
}

async fn handle_revoke_vendor_pub_key<A: ApiAlloc>(
    alloc: &A,
    payload: &[u8],
) -> CaliptraCmdResult<usize> {
    let req = FuseRevokeVendorPubKeyReqPayload::ref_from_bytes(payload)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
    let FuseRevokeVendorPubKeyReqPayload {
        vendor_pk_hash_slot,
        key_type,
        key_index,
        reserved,
    } = *req;

    if reserved != 0 {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let key_type = RevokeVendorPubKeyType::try_from(key_type)
        .map_err(|_| CaliptraCompletionCode::InvalidParameter)?;

    // Check the given slot has a valid PK hash provisioned
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

    let caliptra_info = fw_info(alloc).await?;
    let booted_pk_hash = Caliptra::<DefaultSyscalls>::new()
        .read_vendor_pk_hash()
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    // Check if the key to be revoked was a key used to boot. If so, return an error as a form
    // of proof of possession for other keys.
    if booted_pk_hash == pk_hash_from_slot {
        const FW_VERIFICATION_PQC_TYPE_MLDSA: u32 = 1;
        const FW_VERIFICATION_PQC_TYPE_LMS: u32 = 3;
        let same_key = match (key_type, caliptra_info.image_manifest_pqc_type) {
            (RevokeVendorPubKeyType::Ecdsa384, _) => {
                key_index == caliptra_info.vendor_ecc384_pub_key_index
            }
            // Same PQC type
            (RevokeVendorPubKeyType::Lms, FW_VERIFICATION_PQC_TYPE_LMS)
            | (RevokeVendorPubKeyType::Mldsa87, FW_VERIFICATION_PQC_TYPE_MLDSA) => {
                key_index == caliptra_info.vendor_pqc_pub_key_index
            }
            // Different PQC types
            _ => false,
        };
        if same_key {
            return Err(CaliptraCompletionCode::InvalidParameter);
        }
    }

    otp.revoke_vendor_pub_key(vendor_pk_hash_slot, key_type, key_index)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    Ok(0)
}

async fn handle_revoke_vendor_pk_hash(payload: &[u8]) -> CaliptraCmdResult<usize> {
    // Decode the request
    let req = FuseRevokeVendorPkHashReqPayload::ref_from_bytes(payload)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
    let FuseRevokeVendorPkHashReqPayload {
        vendor_pk_hash_slot,
        reserved,
    } = *req;

    if reserved != 0 {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    const MAX_VENDOR_PK_HASH_SLOTS: u32 = 16;
    if vendor_pk_hash_slot >= MAX_VENDOR_PK_HASH_SLOTS {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    let otp = Otp::<DefaultSyscalls>::new();
    // A cleared validity bit is the persistent indication that this slot was
    // already revoked. Preserve the mailbox policy's idempotent behavior
    // without attempting to read a now-invalid slot.
    if !otp.valid_vendor_pk_hash_slot(vendor_pk_hash_slot) {
        return Ok(0);
    }

    // Check if the PK hash to be revoked was used to boot. If so, return an
    // error as a form of proof of possession for other keys.
    let booted_pk_hash = Caliptra::<DefaultSyscalls>::new()
        .read_vendor_pk_hash()
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let pk_hash_from_slot = otp
        .read_vendor_pk_hash(vendor_pk_hash_slot)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    if booted_pk_hash == pk_hash_from_slot {
        return Err(CaliptraCompletionCode::InvalidParameter);
    }

    otp.revoke_vendor_pk_hash(vendor_pk_hash_slot)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    Ok(0)
}
