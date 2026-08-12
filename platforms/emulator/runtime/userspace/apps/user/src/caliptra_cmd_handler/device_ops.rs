// Licensed under the Apache-2.0 license

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use arrayvec::ArrayVec;
use async_trait::async_trait;
use caliptra_api::mailbox::{EcdsaVerifyReq, MailboxReqHeader, MailboxRespHeader};
use caliptra_mcu_common_commands::{
    CaliptraCmdResult, CaliptraCompletionCode, DEBUG_UNLOCK_CHALLENGE_SIZE,
    DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_libsyscall_caliptra::mailbox::{Mailbox, MailboxError, PayloadStream};
use caliptra_mcu_libsyscall_caliptra::otp::{Otp, RevokeVendorPubKeyType};
use caliptra_mcu_libsyscall_caliptra::{caliptra, otp, DefaultSyscalls};
use caliptra_mcu_libtock_platform::ErrorCode;
use caliptra_mcu_mbox_common::messages::{HybridSignature, AUTH_CMD_NONCE_LEN};
use mcu_caliptra_api_lite::{
    fe_prog, fw_info, get_attested_csr_ecc384, get_attested_csr_mldsa87, get_idev_csr_ecc384,
    hash_all, request_debug_unlock_challenge, rng_generate, ApiAlloc, HashAlgo, McuErrorCode,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
};
use zerocopy::IntoBytes;

const ALGO_ECC_P384: u32 = 0x0001;
const ALGO_MLDSA87: u32 = 0x0002;

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
        .execute(
            PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD,
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

#[allow(clippy::too_many_arguments)]
pub async fn verify_authorized_signatures<A: ApiAlloc>(
    alloc: &A,
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

    // 1. Verify ECC P-384 Signature using Caliptra Mailbox (over SHA-384(pre-image)).
    let mut hash = [0u8; 48];
    hash_all(alloc, HashAlgo::Sha384, pre_image.as_slice(), &mut hash)
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

    mcu_caliptra_api_lite::raw::raw_mailbox_execute(
        cmd_ecdsa_verify,
        ecc_req_bytes,
        ecc_resp_bytes,
    )
    .await
    .map_err(|_| CaliptraCompletionCode::AccessDenied)?;

    // 2. Verify ML-DSA-87 Signature using Caliptra Mailbox (over SHA-512(pre-image)).
    let mut mldsa_msg = [0u8; 64];
    hash_all(
        alloc,
        HashAlgo::Sha512,
        pre_image.as_slice(),
        &mut mldsa_msg,
    )
    .await
    .map_err(|_| CaliptraCompletionCode::OperationFailed)?;

    let mut mldsa_resp = MailboxRespHeader::default();
    let mldsa_resp_bytes = mldsa_resp.as_mut_bytes();
    let cmd_mldsa_verify: u32 = caliptra_api::mailbox::CommandId::MLDSA87_SIGNATURE_VERIFY.into();
    let message_size = (mldsa_msg.len() as u32).to_le_bytes();
    let segments = [
        mldsa_pub.as_slice(),
        sig.mldsa_sig.as_slice(),
        message_size.as_slice(),
        mldsa_msg.as_slice(),
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

pub fn provision_vendor_pk_hash(slot: u32, hash: &[u8; 48]) -> CaliptraCmdResult<()> {
    Otp::<DefaultSyscalls>::new()
        .provision_vendor_pk_hash(slot, hash)
        .map_err(|_| CaliptraCompletionCode::OperationFailed)
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

    let caliptra_info = fw_info(alloc)
        .await
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let booted_pk_hash = caliptra::Caliptra::<DefaultSyscalls>::new()
        .read_vendor_pk_hash()
        .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
    let pk_hash_from_slot = otp
        .read_vendor_pk_hash(vendor_pk_hash_slot)
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
    let otp = Otp::<DefaultSyscalls>::new();
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
