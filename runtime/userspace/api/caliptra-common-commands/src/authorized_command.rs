// Licensed under the Apache-2.0 license

use caliptra_mcu_libsyscall_caliptra::caliptra::Caliptra;
use caliptra_mcu_libsyscall_caliptra::otp::{Otp, RevokeVendorPubKeyType};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_mbox_common::messages::{CommandId, FuseReadResp, MAX_FUSE_DATA_SIZE};
use caliptra_mcu_otp_fuse::{fuse_read_dai_params, PartitionId};
use mcu_caliptra_api_lite::{fe_prog, ApiAlloc, McuErrorCode};
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
        let cmd = self
            .cmd_authorizer
            .is_authorized(self.scratch, cmd_id, req)
            .await
            .map_err(|_| errors::UNAUTHORIZED_COMMAND)?;
        match cmd_id {
            CommandId::MC_PROVISION_VENDOR_PK_HASH => {
                self.handle_provision_vendor_pk_hash(cmd, resp_buf).await
            }
            CommandId::MC_PROVISION_OWNER_PK_HASH => {
                self.handle_provision_owner_pk_hash(cmd, resp_buf).await
            }
            CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN => {
                self.handle_increase_caliptra_min_svn(cmd, resp_buf).await
            }
            CommandId::MC_FE_PROG => self.handle_fe_prog(cmd, resp_buf).await,
            CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY => {
                self.handle_revoke_vendor_pub_key(cmd, resp_buf).await
            }
            CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH => {
                self.handle_revoke_vendor_pk_hash(cmd, resp_buf).await
            }
            CommandId::MC_FUSE_READ => self.handle_fuse_read(cmd, resp_buf).await,
            CommandId::MC_FUSE_WRITE => self.handle_fuse_write(cmd, resp_buf).await,
            CommandId::MC_FUSE_LOCK_PARTITION => {
                self.handle_fuse_lock_partition(cmd, resp_buf).await
            }
            _ => Err(errors::UNSUPPORTED_COMMAND),
        }
    }
}

fn map_mcu_err(e: McuErrorCode) -> CaliptraCompletionCode {
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

async fn handle_fuse_read<'r>(
    &self,
    req: &[u8],
    resp_buf: &'r mut [u8],
) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
    // Decode the request
    let req = FuseReadReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
    let (resp, _) = FuseReadResp::mut_from_prefix(resp_buf).map_err(|_| errors::INVALID_PARAMS)?;

    *resp = FuseReadResp::default();

    let params = fuse_read_dai_params(req.partition, req.entry, MAX_FUSE_DATA_SIZE / 4)
        .map_err(|_| errors::INVALID_PARAMS)?;

    let otp: otp::Otp<DefaultSyscalls> = otp::Otp::new();

    // Create a iterator over the words in the response that yields at most `params.words_to_read`
    // (which is less or equal to the words in resp.data).
    let words = resp.data.chunks_exact_mut(4).take(params.words_to_read);
    for (i, word) in words.enumerate() {
        let data = otp
            .read_raw(params.base_word_addr as u32, i as u32)
            .map_err(|_| errors::MCU_MBOX_COMMON)?;
        let bytes = data.to_ne_bytes();
        word.copy_from_slice(&bytes);
    }

    resp.length_bits = params.valid_bits;

    Ok((resp.as_mut_bytes(), MbxCmdStatus::Complete))
}

async fn handle_fuse_write<'r>(
    &self,
    req: &[u8],
    resp_buf: &'r mut [u8],
) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
    // Decode the request
    let req = FuseWriteReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
    let (resp, _) = FuseWriteResp::mut_from_prefix(resp_buf).map_err(|_| errors::INVALID_PARAMS)?;

    let otp: otp::Otp<DefaultSyscalls> = otp::Otp::new();

    otp.write_raw(req.word_addr, req.data, req.mask)
        .map_err(|e| match e {
            caliptra_mcu_libtock_platform::ErrorCode::Fail => errors::MCU_MBOX_COMMON,
            caliptra_mcu_libtock_platform::ErrorCode::Invalid => errors::INVALID_PARAMS,
            _ => errors::MCU_MBOX_COMMON,
        })?;

    *resp = FuseWriteResp::default();

    Ok((resp.as_mut_bytes(), MbxCmdStatus::Complete))
}

async fn handle_fuse_lock_partition<'r>(
    &self,
    req: &[u8],
    resp_buf: &'r mut [u8],
) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
    // Decode the request
    let req = FuseLockPartitionReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

    Otp::<DefaultSyscalls>::new()
        .lock_partition(partition)
        .map_err(|error| match error {
            ErrorCode::Invalid => CaliptraCompletionCode::InvalidParameter,
            _ => CaliptraCompletionCode::OperationFailed,
        })?;

    Ok(0)
}

async fn handle_provision_vendor_pk_hash<'r>(
    &self,
    req: &[u8],
    resp_buf: &'r mut [u8],
) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
    let req = ProvisionVendorPkHashReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

    Otp::<DefaultSyscalls>::new()
        .provision_vendor_pk_hash(slot, hash)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    Ok(0)
}

async fn handle_provision_owner_pk_hash<'r>(
    &self,
    req: &[u8],
    resp_buf: &'r mut [u8],
) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
    let req = ProvisionOwnerPkHashReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

    Otp::<DefaultSyscalls>::new()
        .provision_owner_pk_hash(hash)
        .map_err(|error| match error {
            ErrorCode::Invalid => CaliptraCompletionCode::InvalidParameter,
            _ => CaliptraCompletionCode::OperationFailed,
        })?;

    Ok(0)
}

async fn handle_increase_caliptra_min_svn<'r>(
    &self,
    req: &[u8],
    resp_buf: &'r mut [u8],
) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
    if resp_buf.len() < core::mem::size_of::<FuseIncreaseCaliptraMinSvnResp>() {
        return Err(errors::INVALID_PARAMS);
    }

    // Decode the request
    let req =
        FuseIncreaseCaliptraMinSvnReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

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
    Ok(0)
}

async fn handle_fe_prog<'r>(
    &self,
    req: &[u8],
    resp_buf: &'r mut [u8],
) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
    // Decode the request
    let req = McuFeProgReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
    let (resp, _) = FuseWriteResp::mut_from_prefix(resp_buf).map_err(|_| errors::INVALID_PARAMS)?;

    self.non_crypto_cmds_handler
        .program_field_entropy(self.scratch, req.partition)
        .await
        .map_err(|_| errors::MCU_MBOX_COMMON)?;

    *resp = FuseWriteResp::default();
    let resp_len = resp.as_bytes().len();
    Ok((&mut resp_buf[..resp_len], MbxCmdStatus::Complete))
}

async fn handle_revoke_vendor_pub_key<'r>(
    &self,
    req: &[u8],
    resp_buf: &'r mut [u8],
) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
    let req = FuseRevokeVendorPubKeyReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

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
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    Ok(0)
}

async fn handle_revoke_vendor_pk_hash<'r>(
    &self,
    req: &[u8],
    resp_buf: &'r mut [u8],
) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
    // Decode the request
    let req = FuseRevokeVendorPkHashReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

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
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    Ok(0)
}
