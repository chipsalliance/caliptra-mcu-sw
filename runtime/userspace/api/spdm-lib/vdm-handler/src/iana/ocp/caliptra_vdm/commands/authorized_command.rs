// Licensed under the Apache-2.0 license

//! AUTHORIZED_COMMAND (0x12): dispatches authorization subcommands.

use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use crate::iana::ocp::caliptra_vdm::CaliptraVdmAuthorization;
use caliptra_mcu_mbox_common::messages::{
    CommandId, DotLockPayload, HybridSignature, AUTH_CMD_NONCE_LEN,
};
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult, CaliptraVdmResult,
};
use zerocopy::FromBytes;

/// ECC P-384 public-key coordinate size (bytes).
const ECC_P384_COORD_SIZE: usize = 48;
/// ML-DSA-87 public-key size (bytes).
const MLDSA87_PUB_KEY_SIZE: usize = 2592;
const FE_PROG_PAYLOAD_LEN: usize = 4;
const PROVISION_VENDOR_PK_HASH_PAYLOAD_LEN: usize = 4 + 48;
const PROVISION_OWNER_PK_HASH_PAYLOAD_LEN: usize = 48;
const INCREASE_CALIPTRA_MIN_SVN_PAYLOAD_LEN: usize = 4 + 4;
const REVOKE_VENDOR_PUB_KEY_PAYLOAD_LEN: usize = 4 + 4 + 4 + 4;
const REVOKE_VENDOR_PK_HASH_PAYLOAD_LEN: usize = 4 + 4;
const FUSE_LOCK_PARTITION_PAYLOAD_LEN: usize = 4;
const DOT_LOCK_PAYLOAD_LEN: usize = 4 + core::mem::size_of::<DotLockPayload>();

/// MC_GET_AUTH_CMD_CHALLENGE sub-command (`MACC`).
pub const GET_AUTH_CHALLENGE_CMD_ID: u32 = 0x4D41_4343;
/// MC_PROVISION_VENDOR_PK_HASH sub-command (`PVPK`).
pub const PROVISION_VENDOR_PK_HASH_CMD_ID: u32 = 0x5056_504B;
/// MC_PROVISION_OWNER_PK_HASH sub-command (`POPK`).
pub const PROVISION_OWNER_PK_HASH_CMD_ID: u32 = CommandId::MC_PROVISION_OWNER_PK_HASH.0;
/// MC_FUSE_INCREASE_CALIPTRA_MIN_SVN sub-command (`MCMS`).
pub const INCREASE_CALIPTRA_MIN_SVN_CMD_ID: u32 = 0x4D43_4D53;
/// MC_FE_PROG sub-command (`MCFP`).
pub const FE_PROG_CMD_ID: u32 = 0x4D43_4650;
/// MC_FUSE_REVOKE_VENDOR_PUB_KEY sub-command (`MRVK`).
pub const REVOKE_VENDOR_PUB_KEY_CMD_ID: u32 = 0x4D52_564B;
/// MC_FUSE_REVOKE_VENDOR_PK_HASH sub-command (`RVKH`).
pub const REVOKE_VENDOR_PK_HASH_CMD_ID: u32 = 0x5256_4B48;
/// MC_FUSE_LOCK_PARTITION sub-command (`IFPK`).
pub const FUSE_LOCK_PARTITION_CMD_ID: u32 = CommandId::MC_FUSE_LOCK_PARTITION.0;
/// Device Ownership Transfer command family (`0x11`).
pub const DEVICE_OWNERSHIP_TRANSFER_CMD_ID: u32 = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0;
/// DOT_LOCK sub-command (`MDLK`).
pub const DOT_LOCK_CMD_ID: u32 = CommandId::MC_DOT_LOCK.0;

pub(crate) async fn handle<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let Some(sub_cmd_bytes) = req.get(..4) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    let sub_cmd = u32::from_le_bytes([
        sub_cmd_bytes[0],
        sub_cmd_bytes[1],
        sub_cmd_bytes[2],
        sub_cmd_bytes[3],
    ]);
    let payload = &req[4..];
    match sub_cmd {
        GET_AUTH_CHALLENGE_CMD_ID => handle_get_auth_challenge(cmds, payload, scratch, out).await,
        PROVISION_VENDOR_PK_HASH_CMD_ID => {
            handle_provision_vendor_pk_hash(cmds, payload, scratch, out).await
        }
        PROVISION_OWNER_PK_HASH_CMD_ID => {
            handle_provision_owner_pk_hash(cmds, payload, scratch, out).await
        }
        INCREASE_CALIPTRA_MIN_SVN_CMD_ID => {
            handle_increase_caliptra_min_svn(cmds, payload, scratch, out).await
        }
        FE_PROG_CMD_ID => handle_fe_prog(cmds, payload, scratch, out).await,
        REVOKE_VENDOR_PUB_KEY_CMD_ID => {
            handle_revoke_vendor_pub_key(cmds, payload, scratch, out).await
        }
        REVOKE_VENDOR_PK_HASH_CMD_ID => {
            handle_revoke_vendor_pk_hash(cmds, payload, scratch, out).await
        }
        FUSE_LOCK_PARTITION_CMD_ID => handle_fuse_lock_partition(cmds, payload, scratch, out).await,
        #[cfg(feature = "device-ownership-transfer")]
        DEVICE_OWNERSHIP_TRANSFER_CMD_ID => {
            handle_device_ownership_transfer(cmds, payload, scratch, out).await
        }
        _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    }
}

async fn handle_device_ownership_transfer<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    // `req` starts with the little-endian DOT FourCC and remains byte-exact
    // through authorization. The platform therefore verifies the common
    // transcript `family 0x11 (BE) || req || nonce` without re-encoding fields.
    let Some(subcommand) = req.get(..4) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    match read_u32_le(subcommand) {
        DOT_LOCK_CMD_ID => handle_dot_lock(cmds, req, scratch, out).await,
        _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    }
}

async fn handle_dot_lock<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let parsed = match split_authorized_request(req, DOT_LOCK_PAYLOAD_LEN) {
        Ok(parsed) => parsed,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let subcommand = read_u32_le(&parsed.payload[..4]);
    match subcommand {
        DOT_LOCK_CMD_ID => {
            let Ok(request) = DotLockPayload::ref_from_bytes(&parsed.payload[4..]) else {
                return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter);
            };
            finish_authorized_command(
                cmds.dot_lock(
                    request,
                    parsed.payload,
                    parsed.sig,
                    parsed.nonce,
                    parsed.ecc_pub_x,
                    parsed.ecc_pub_y,
                    parsed.mldsa_pub,
                    scratch,
                )
                .await,
                out,
            )
        }
        _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    }
}

async fn handle_get_auth_challenge<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    if let Err(code) = super::require_empty(req) {
        return CaliptraVdmCmdResult::Error(code);
    }
    let data = match super::write_success(out) {
        Ok(data) => data,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    match cmds.get_auth_challenge(scratch, data).await {
        Ok(n) => CaliptraVdmCmdResult::Response(1 + n),
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}

async fn handle_provision_vendor_pk_hash<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let parsed = match split_authorized_request(req, PROVISION_VENDOR_PK_HASH_PAYLOAD_LEN) {
        Ok(parsed) => parsed,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let slot = read_u32_le(&parsed.payload[..4]);
    let hash = match <&[u8; ECC_P384_COORD_SIZE]>::try_from(&parsed.payload[4..]) {
        Ok(hash) => hash,
        Err(_) => return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    };
    finish_authorized_command(
        cmds.provision_vendor_pk_hash(
            slot,
            hash,
            parsed.payload,
            parsed.sig,
            parsed.nonce,
            parsed.ecc_pub_x,
            parsed.ecc_pub_y,
            parsed.mldsa_pub,
            scratch,
        )
        .await,
        out,
    )
}

async fn handle_provision_owner_pk_hash<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let parsed = match split_authorized_request(req, PROVISION_OWNER_PK_HASH_PAYLOAD_LEN) {
        Ok(parsed) => parsed,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let hash = match <&[u8; ECC_P384_COORD_SIZE]>::try_from(parsed.payload) {
        Ok(hash) => hash,
        Err(_) => return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    };
    finish_authorized_command(
        cmds.provision_owner_pk_hash(
            hash,
            parsed.payload,
            parsed.sig,
            parsed.nonce,
            parsed.ecc_pub_x,
            parsed.ecc_pub_y,
            parsed.mldsa_pub,
            scratch,
        )
        .await,
        out,
    )
}

async fn handle_increase_caliptra_min_svn<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let parsed = match split_authorized_request(req, INCREASE_CALIPTRA_MIN_SVN_PAYLOAD_LEN) {
        Ok(parsed) => parsed,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let flags = read_u32_le(&parsed.payload[..4]);
    let svn = read_u32_le(&parsed.payload[4..8]);
    finish_authorized_command(
        cmds.increase_caliptra_min_svn(
            flags,
            svn,
            parsed.payload,
            parsed.sig,
            parsed.nonce,
            parsed.ecc_pub_x,
            parsed.ecc_pub_y,
            parsed.mldsa_pub,
            scratch,
        )
        .await,
        out,
    )
}

async fn handle_fe_prog<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let parsed = match split_authorized_request(req, FE_PROG_PAYLOAD_LEN) {
        Ok(parsed) => parsed,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let partition = read_u32_le(parsed.payload);
    match cmds
        .program_field_entropy(
            partition,
            parsed.sig,
            parsed.nonce,
            parsed.ecc_pub_x,
            parsed.ecc_pub_y,
            parsed.mldsa_pub,
            scratch,
        )
        .await
    {
        Ok(()) => match super::write_success(out) {
            Ok(_) => CaliptraVdmCmdResult::Response(1),
            Err(code) => CaliptraVdmCmdResult::Error(code),
        },
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}

async fn handle_revoke_vendor_pub_key<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let parsed = match split_authorized_request(req, REVOKE_VENDOR_PUB_KEY_PAYLOAD_LEN) {
        Ok(parsed) => parsed,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let reserved = read_u32_le(&parsed.payload[..4]);
    let slot = read_u32_le(&parsed.payload[4..8]);
    let key_type = read_u32_le(&parsed.payload[8..12]);
    let key_index = read_u32_le(&parsed.payload[12..16]);
    finish_authorized_command(
        cmds.revoke_vendor_pub_key(
            reserved,
            slot,
            key_type,
            key_index,
            parsed.payload,
            parsed.sig,
            parsed.nonce,
            parsed.ecc_pub_x,
            parsed.ecc_pub_y,
            parsed.mldsa_pub,
            scratch,
        )
        .await,
        out,
    )
}

async fn handle_revoke_vendor_pk_hash<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let parsed = match split_authorized_request(req, REVOKE_VENDOR_PK_HASH_PAYLOAD_LEN) {
        Ok(parsed) => parsed,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let reserved = read_u32_le(&parsed.payload[..4]);
    let slot = read_u32_le(&parsed.payload[4..8]);
    finish_authorized_command(
        cmds.revoke_vendor_pk_hash(
            reserved,
            slot,
            parsed.payload,
            parsed.sig,
            parsed.nonce,
            parsed.ecc_pub_x,
            parsed.ecc_pub_y,
            parsed.mldsa_pub,
            scratch,
        )
        .await,
        out,
    )
}

async fn handle_fuse_lock_partition<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let parsed = match split_authorized_request(req, FUSE_LOCK_PARTITION_PAYLOAD_LEN) {
        Ok(parsed) => parsed,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let partition = read_u32_le(parsed.payload);
    finish_authorized_command(
        cmds.fuse_lock_partition(
            partition,
            parsed.payload,
            parsed.sig,
            parsed.nonce,
            parsed.ecc_pub_x,
            parsed.ecc_pub_y,
            parsed.mldsa_pub,
            scratch,
        )
        .await,
        out,
    )
}

/// Borrowed view of an authorized request: the subcommand payload followed by
/// the common authorization trailer (challenge nonce, hybrid public key, and
/// hybrid signature).
struct AuthorizedRequest<'a> {
    payload: &'a [u8],
    nonce: &'a [u8; AUTH_CMD_NONCE_LEN],
    ecc_pub_x: &'a [u8; ECC_P384_COORD_SIZE],
    ecc_pub_y: &'a [u8; ECC_P384_COORD_SIZE],
    mldsa_pub: &'a [u8; MLDSA87_PUB_KEY_SIZE],
    sig: &'a HybridSignature,
}

fn split_authorized_request(
    req: &[u8],
    payload_len: usize,
) -> Result<AuthorizedRequest<'_>, CaliptraCompletionCode> {
    let auth_len = AUTH_CMD_NONCE_LEN
        + 2 * ECC_P384_COORD_SIZE
        + MLDSA87_PUB_KEY_SIZE
        + core::mem::size_of::<HybridSignature>();
    let expected_len = payload_len
        .checked_add(auth_len)
        .ok_or(CaliptraCompletionCode::InvalidPayloadSize)?;
    if req.len() != expected_len {
        return Err(CaliptraCompletionCode::InvalidPayloadSize);
    }
    let (payload, auth) = req.split_at(payload_len);
    let (nonce, auth) = auth.split_at(AUTH_CMD_NONCE_LEN);
    let (ecc_pub_x, auth) = auth.split_at(ECC_P384_COORD_SIZE);
    let (ecc_pub_y, auth) = auth.split_at(ECC_P384_COORD_SIZE);
    let (mldsa_pub, sig_bytes) = auth.split_at(MLDSA87_PUB_KEY_SIZE);
    const INVALID: CaliptraCompletionCode = CaliptraCompletionCode::InvalidParameter;
    Ok(AuthorizedRequest {
        payload,
        nonce: <&[u8; AUTH_CMD_NONCE_LEN]>::try_from(nonce).map_err(|_| INVALID)?,
        ecc_pub_x: <&[u8; ECC_P384_COORD_SIZE]>::try_from(ecc_pub_x).map_err(|_| INVALID)?,
        ecc_pub_y: <&[u8; ECC_P384_COORD_SIZE]>::try_from(ecc_pub_y).map_err(|_| INVALID)?,
        mldsa_pub: <&[u8; MLDSA87_PUB_KEY_SIZE]>::try_from(mldsa_pub).map_err(|_| INVALID)?,
        sig: HybridSignature::ref_from_bytes(sig_bytes).map_err(|_| INVALID)?,
    })
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn finish_authorized_command(
    result: CaliptraVdmResult<()>,
    out: &mut [u8],
) -> CaliptraVdmCmdResult {
    match result {
        Ok(()) => match super::write_success(out) {
            Ok(_) => CaliptraVdmCmdResult::Response(1),
            Err(code) => CaliptraVdmCmdResult::Error(code),
        },
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
