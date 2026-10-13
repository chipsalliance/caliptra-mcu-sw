// Licensed under the Apache-2.0 license

use crate::{CaliptraCmdHandler, CaliptraCmdResult, CaliptraCompletionCode, CommandAuthorizer};
use caliptra_mcu_mbox_common::messages::{
    CommandId, DotDisablePayload, DotLockPayload, DotRotatePayload, HybridSignature, SvnTarget,
    AUTH_CMD_NONCE_LEN, MAX_FUSE_DATA_SIZE,
};
#[cfg(feature = "device-ownership-transfer")]
use caliptra_mcu_mbox_common::messages::{
    DotOverrideChallengePayload, DotOverridePayload, DotStatus, DotUnlockPayload, DOT_BLOB_SIZE,
};
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_mbox_common::messages::{EndorsementAlgorithm, HpkeHandle, SekState};
use mcu_caliptra_api::ScratchAlloc;
#[cfg(feature = "ocp-lock")]
use zerocopy::byteorder::little_endian::U16;
use zerocopy::byteorder::little_endian::U32;
#[cfg(feature = "device-ownership-transfer")]
use zerocopy::IntoBytes;
use zerocopy::{FromBytes, Immutable, KnownLayout};

const U32_LEN: usize = core::mem::size_of::<u32>();
const ECC_P384_COORD_LEN: usize = 48;
const MLDSA87_PUB_KEY_LEN: usize = 2592;
const AUTHORIZATION_TRAILER_LEN: usize = AUTH_CMD_NONCE_LEN
    + 2 * ECC_P384_COORD_LEN
    + MLDSA87_PUB_KEY_LEN
    + core::mem::size_of::<HybridSignature>();

#[cfg(feature = "device-ownership-transfer")]
const MAX_AUTHORIZED_PAYLOAD_LEN: usize = U32_LEN + core::mem::size_of::<DotRotatePayload>();
#[cfg(not(feature = "device-ownership-transfer"))]
const MAX_AUTHORIZED_PAYLOAD_LEN: usize = U32_LEN + 48;

/// Largest canonical AuthorizedCommand body, including its target ID.
pub const MAX_AUTHORIZED_REQUEST_LEN: usize =
    U32_LEN + MAX_AUTHORIZED_PAYLOAD_LEN + AUTHORIZATION_TRAILER_LEN;

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct WireCommandId {
    value: U32,
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct ProvisionVendorPkHashPayload {
    slot: U32,
    hash: [u8; 48],
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct ProvisionOwnerPkHashPayload {
    hash: [u8; 48],
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct IncreaseMinSvnPayload {
    flags: U32,
    target: U32,
    svn: U32,
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct FieldEntropyPayload {
    partition: U32,
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct RevokeVendorPubKeyPayload {
    reserved: U32,
    slot: U32,
    key_type: U32,
    key_index: U32,
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct RevokeVendorPkHashPayload {
    reserved: U32,
    slot: U32,
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct FuseLockPartitionPayload {
    partition: U32,
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct FuseReadPayload {
    partition: U32,
    entry: U32,
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct FuseWritePayload {
    word_addr: U32,
    data: U32,
    mask: U32,
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct ZeroizeUdsFeAndEnterRmaPayload {
    rma_token: [u8; 16],
}

#[cfg(feature = "ocp-lock")]
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct OcpLockEpochKeyReportPayload {
    nonce: [u8; 32],
    sek_state: U16,
    _reserved: U16,
    algorithm: U32,
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout)]
struct AuthorizationBlock {
    nonce: [u8; AUTH_CMD_NONCE_LEN],
    ecc_pub_x: [u8; ECC_P384_COORD_LEN],
    ecc_pub_y: [u8; ECC_P384_COORD_LEN],
    mldsa_pub: [u8; MLDSA87_PUB_KEY_LEN],
    signature: HybridSignature,
}

const _: () = assert!(core::mem::size_of::<AuthorizationBlock>() == AUTHORIZATION_TRAILER_LEN);

/// Result data produced by a transport-independent command executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandResponse {
    Empty,
    Data(usize),
    ResetRequired,
}

/// Commands exposed by a transport using the shared dispatcher.
#[derive(Debug, Clone, Copy)]
pub struct CommandPolicy {
    pub allow_raw_fuse: bool,
    pub allow_dot: bool,
    pub allow_ocp_lock: bool,
    pub allow_native_ocp_lock: bool,
}

impl CommandPolicy {
    pub const MCI: Self = Self {
        allow_raw_fuse: true,
        allow_dot: true,
        allow_ocp_lock: true,
        allow_native_ocp_lock: true,
    };

    pub const SPDM: Self = Self {
        allow_raw_fuse: false,
        allow_dot: true,
        allow_ocp_lock: true,
        allow_native_ocp_lock: false,
    };
}

struct AuthorizedRequest<'a> {
    payload: &'a [u8],
    authorization: &'a AuthorizationBlock,
}

/// Executes a canonical AuthorizedCommand body.
///
/// `request` starts with a four-byte little-endian target ID. Family targets
/// (`0x11` and `0x13`) carry a second four-byte operation ID in their signed
/// payload.
pub async fn execute_authorized<H, Auth, Alloc>(
    commands: &H,
    authorizer: &Auth,
    alloc: &Alloc,
    request: &[u8],
    output: &mut [u8],
    policy: CommandPolicy,
) -> CaliptraCmdResult<CommandResponse>
where
    H: CaliptraCmdHandler,
    Auth: CommandAuthorizer,
    Alloc: ScratchAlloc,
{
    let (target_id, request) = split_id(request)?;
    if CommandId::from(target_id).is_vendor_unique() {
        return Err(CaliptraCompletionCode::UnsupportedOperation);
    }

    if target_id == CommandId::MC_GET_AUTH_CMD_CHALLENGE.0 {
        if !request.is_empty() {
            return Err(CaliptraCompletionCode::InvalidPayloadSize);
        }
        let output = output
            .get_mut(..AUTH_CMD_NONCE_LEN)
            .ok_or(CaliptraCompletionCode::InsufficientResources)?;
        let challenge = authorizer
            .generate_challenge(alloc)
            .await
            .map_err(|_| CaliptraCompletionCode::OperationFailed)?;
        output.copy_from_slice(&challenge);
        authorizer.set_challenge(challenge);
        return Ok(CommandResponse::Data(AUTH_CMD_NONCE_LEN));
    }

    if matches!(
        target_id,
        value if value == CommandId::MC_FUSE_READ.0 || value == CommandId::MC_FUSE_WRITE.0
    ) && !policy.allow_raw_fuse
    {
        return Err(CaliptraCompletionCode::UnsupportedOperation);
    }
    if target_id == CommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0
        && (!policy.allow_dot || !cfg!(feature = "device-ownership-transfer"))
    {
        return Err(CaliptraCompletionCode::UnsupportedOperation);
    }
    if target_id == CommandId::MC_OCP_LOCK.0
        && (!policy.allow_ocp_lock || !cfg!(feature = "ocp-lock"))
    {
        return Err(CaliptraCompletionCode::UnsupportedOperation);
    }

    let payload_len = authorized_payload_len(target_id, request)?;
    let parsed = split_authorized_request(request, payload_len)?;
    authorizer
        .verify_signatures(
            alloc,
            target_id,
            parsed.payload,
            &parsed.authorization.nonce,
            &parsed.authorization.ecc_pub_x,
            &parsed.authorization.ecc_pub_y,
            &parsed.authorization.mldsa_pub,
            &parsed.authorization.signature,
        )
        .await
        .map_err(|_| CaliptraCompletionCode::AccessDenied)?;

    match target_id {
        value if value == CommandId::MC_PROVISION_VENDOR_PK_HASH.0 => {
            let payload = ProvisionVendorPkHashPayload::ref_from_bytes(parsed.payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands
                .provision_vendor_pk_hash(payload.slot.get(), &payload.hash)
                .await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_PROVISION_OWNER_PK_HASH.0 => {
            let payload = ProvisionOwnerPkHashPayload::ref_from_bytes(parsed.payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands.provision_owner_pk_hash(&payload.hash).await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_FUSE_INCREASE_MIN_SVN.0 => {
            let payload = IncreaseMinSvnPayload::ref_from_bytes(parsed.payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            if payload.flags.get() != 0 {
                return Err(CaliptraCompletionCode::InvalidParameter);
            }
            let target = SvnTarget::try_from(payload.target.get())
                .map_err(|_| CaliptraCompletionCode::InvalidParameter)?;
            commands
                .increase_min_svn(alloc, target, payload.svn.get())
                .await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_FE_PROG.0 => {
            let payload = FieldEntropyPayload::ref_from_bytes(parsed.payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands
                .program_field_entropy(alloc, payload.partition.get())
                .await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY.0 => {
            let payload = RevokeVendorPubKeyPayload::ref_from_bytes(parsed.payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            if payload.reserved.get() != 0 {
                return Err(CaliptraCompletionCode::InvalidParameter);
            }
            commands
                .revoke_vendor_pub_key(
                    alloc,
                    payload.slot.get(),
                    payload.key_type.get(),
                    payload.key_index.get(),
                )
                .await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH.0 => {
            let payload = RevokeVendorPkHashPayload::ref_from_bytes(parsed.payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            if payload.reserved.get() != 0 {
                return Err(CaliptraCompletionCode::InvalidParameter);
            }
            commands.revoke_vendor_pk_hash(payload.slot.get()).await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_FUSE_LOCK_PARTITION.0 => {
            let payload = FuseLockPartitionPayload::ref_from_bytes(parsed.payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands
                .fuse_lock_partition(payload.partition.get())
                .await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_FUSE_READ.0 => {
            execute_fuse_read(commands, parsed.payload, output).await
        }
        value if value == CommandId::MC_FUSE_WRITE.0 => {
            let payload = FuseWritePayload::ref_from_bytes(parsed.payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands
                .fuse_write(
                    payload.word_addr.get(),
                    payload.data.get(),
                    payload.mask.get(),
                )
                .await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_ZEROIZE_UDS_FE_AND_ENTER_RMA.0 => {
            let payload = ZeroizeUdsFeAndEnterRmaPayload::ref_from_bytes(parsed.payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands
                .zeroize_uds_fe_and_enter_rma(&payload.rma_token)
                .await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0 => {
            execute_authorized_dot(commands, alloc, parsed.payload, output).await
        }
        value if value == CommandId::MC_OCP_LOCK.0 => {
            execute_authorized_ocp_lock(commands, alloc, parsed.payload).await
        }
        _ => Err(CaliptraCompletionCode::InvalidParameter),
    }
}

/// Executes a native DOT family body beginning with a four-byte operation ID.
#[cfg(feature = "device-ownership-transfer")]
pub async fn execute_dot<H, Alloc>(
    commands: &H,
    alloc: &Alloc,
    request: &[u8],
    output: &mut [u8],
) -> CaliptraCmdResult<CommandResponse>
where
    H: CaliptraCmdHandler,
    Alloc: ScratchAlloc,
{
    let (subcommand, payload) = split_id(request)?;
    match subcommand {
        value
            if value == CommandId::MC_DOT_ENABLE.0
                || value == CommandId::MC_DOT_LOCK.0
                || value == CommandId::MC_DOT_DISABLE.0
                || value == CommandId::MC_DOT_ROTATE.0
                || value == CommandId::MC_GET_DOT_BACKUP_BLOB.0 =>
        {
            Err(CaliptraCompletionCode::AccessDenied)
        }
        value if value == CommandId::MC_DOT_UNLOCK_CHALLENGE.0 => {
            require_empty(payload)?;
            let challenge = commands.dot_unlock_challenge(alloc).await?;
            write_output(output, &challenge)
        }
        value if value == CommandId::MC_DOT_STATUS.0 => {
            require_empty(payload)?;
            let mut status = DotStatus::default();
            commands.dot_status(&mut status).await?;
            write_output(output, status.as_bytes())
        }
        value if value == CommandId::MC_DOT_RECOVERY.0 => {
            let blob = <&[u8; DOT_BLOB_SIZE]>::try_from(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands.dot_recovery(alloc, blob).await?;
            Ok(CommandResponse::ResetRequired)
        }
        value if value == CommandId::MC_DOT_OVERRIDE_CHALLENGE.0 => {
            let request = DotOverrideChallengePayload::ref_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            let challenge = commands.dot_override_challenge(alloc, request).await?;
            write_output(output, &challenge)
        }
        value if value == CommandId::MC_DOT_OVERRIDE.0 => {
            let request = DotOverridePayload::ref_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands.dot_override(alloc, request).await?;
            Ok(CommandResponse::ResetRequired)
        }
        value if value == CommandId::MC_DOT_UNLOCK.0 => {
            let request = DotUnlockPayload::ref_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands.dot_unlock(alloc, request).await?;
            Ok(CommandResponse::ResetRequired)
        }
        _ => Err(CaliptraCompletionCode::InvalidParameter),
    }
}

/// Executes a native OCP LOCK family body. Native operations remain MCI-only.
#[cfg(feature = "ocp-lock")]
pub async fn execute_ocp_lock<H, Alloc>(
    commands: &H,
    alloc: &Alloc,
    request: &[u8],
    output: &mut [u8],
    policy: CommandPolicy,
) -> CaliptraCmdResult<CommandResponse>
where
    H: CaliptraCmdHandler,
    Alloc: ScratchAlloc,
{
    let (subcommand, payload) = split_id(request)?;
    match subcommand {
        value
            if value == CommandId::MC_OCP_LOCK_ROTATE_HEK.0
                || value == CommandId::MC_OCP_LOCK_SET_PERMA_HEK.0 =>
        {
            Err(CaliptraCompletionCode::AccessDenied)
        }
        _ if !policy.allow_native_ocp_lock => Err(CaliptraCompletionCode::InvalidParameter),
        value if value == CommandId::MC_GET_OCP_LOCK_ENDORSEMENT_CERT.0 => {
            let (handle, payload) = HpkeHandle::read_from_prefix(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            let algorithm = U32::read_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            let len = commands
                .get_ocp_lock_endorsement_cert(
                    alloc,
                    &handle,
                    EndorsementAlgorithm(algorithm.get()),
                    output,
                )
                .await?;
            Ok(CommandResponse::Data(len))
        }
        value if value == CommandId::MC_OCP_LOCK_ENUMERATE_HPKE_HANDLES.0 => {
            require_empty(payload)?;
            let len = commands.ocp_lock_enumerate_hpke_handles(output).await?;
            Ok(CommandResponse::Data(len))
        }
        value if value == CommandId::MC_GET_OCP_LOCK_EPOCH_KEY_REPORT.0 => {
            let payload = OcpLockEpochKeyReportPayload::ref_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            let sek_state = SekState::try_from(payload.sek_state.get())
                .map_err(|_| CaliptraCompletionCode::InvalidParameter)?;
            let algorithm = EndorsementAlgorithm(payload.algorithm.get());
            let len = commands
                .get_ocp_lock_epoch_key_report(alloc, &payload.nonce, sek_state, algorithm, output)
                .await?;
            Ok(CommandResponse::Data(len))
        }
        _ => Err(CaliptraCompletionCode::InvalidParameter),
    }
}

fn authorized_payload_len(target_id: u32, request: &[u8]) -> CaliptraCmdResult<usize> {
    match target_id {
        value if value == CommandId::MC_PROVISION_VENDOR_PK_HASH.0 => {
            Ok(core::mem::size_of::<ProvisionVendorPkHashPayload>())
        }
        value if value == CommandId::MC_PROVISION_OWNER_PK_HASH.0 => {
            Ok(core::mem::size_of::<ProvisionOwnerPkHashPayload>())
        }
        value if value == CommandId::MC_FUSE_INCREASE_MIN_SVN.0 => {
            Ok(core::mem::size_of::<IncreaseMinSvnPayload>())
        }
        value if value == CommandId::MC_FE_PROG.0 => {
            Ok(core::mem::size_of::<FieldEntropyPayload>())
        }
        value if value == CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY.0 => {
            Ok(core::mem::size_of::<RevokeVendorPubKeyPayload>())
        }
        value if value == CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH.0 => {
            Ok(core::mem::size_of::<RevokeVendorPkHashPayload>())
        }
        value if value == CommandId::MC_FUSE_LOCK_PARTITION.0 => {
            Ok(core::mem::size_of::<FuseLockPartitionPayload>())
        }
        value if value == CommandId::MC_FUSE_READ.0 => Ok(core::mem::size_of::<FuseReadPayload>()),
        value if value == CommandId::MC_FUSE_WRITE.0 => {
            Ok(core::mem::size_of::<FuseWritePayload>())
        }
        value if value == CommandId::MC_ZEROIZE_UDS_FE_AND_ENTER_RMA.0 => {
            Ok(core::mem::size_of::<ZeroizeUdsFeAndEnterRmaPayload>())
        }
        value if value == CommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0 => {
            authorized_dot_payload_len(request)
        }
        value if value == CommandId::MC_OCP_LOCK.0 => authorized_ocp_lock_payload_len(request),
        _ => Err(CaliptraCompletionCode::InvalidParameter),
    }
}

fn authorized_dot_payload_len(request: &[u8]) -> CaliptraCmdResult<usize> {
    let (subcommand, _) = split_id(request)?;
    match subcommand {
        value if value == CommandId::MC_DOT_ENABLE.0 => Ok(U32_LEN),
        value if value == CommandId::MC_DOT_LOCK.0 => {
            Ok(U32_LEN + core::mem::size_of::<DotLockPayload>())
        }
        value if value == CommandId::MC_DOT_DISABLE.0 => {
            Ok(U32_LEN + core::mem::size_of::<DotDisablePayload>())
        }
        value if value == CommandId::MC_DOT_ROTATE.0 => {
            Ok(U32_LEN + core::mem::size_of::<DotRotatePayload>())
        }
        value if value == CommandId::MC_GET_DOT_BACKUP_BLOB.0 => Ok(U32_LEN),
        _ => Err(CaliptraCompletionCode::InvalidParameter),
    }
}

fn authorized_ocp_lock_payload_len(request: &[u8]) -> CaliptraCmdResult<usize> {
    let (subcommand, _) = split_id(request)?;
    match subcommand {
        value if value == CommandId::MC_OCP_LOCK_PROGRAM_HEK.0 => Ok(U32_LEN + U32_LEN),
        value if value == CommandId::MC_OCP_LOCK_ZERO_HEK.0 => Ok(U32_LEN + U32_LEN),
        value if value == CommandId::MC_OCP_LOCK_ROTATE_HEK.0 => Ok(U32_LEN + U32_LEN),
        value if value == CommandId::MC_OCP_LOCK_SET_PERMA_HEK.0 => Ok(U32_LEN),
        _ => Err(CaliptraCompletionCode::InvalidParameter),
    }
}

async fn execute_fuse_read<H: CaliptraCmdHandler>(
    commands: &H,
    payload: &[u8],
    output: &mut [u8],
) -> CaliptraCmdResult<CommandResponse> {
    let data = output
        .get_mut(U32_LEN..U32_LEN + MAX_FUSE_DATA_SIZE)
        .ok_or(CaliptraCompletionCode::InsufficientResources)?;
    let payload = FuseReadPayload::ref_from_bytes(payload)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
    let valid_bits = commands
        .fuse_read(payload.partition.get(), payload.entry.get(), data)
        .await?;
    let data_len = (valid_bits as usize).div_ceil(8);
    if data_len > data.len() {
        return Err(CaliptraCompletionCode::OperationFailed);
    }
    output[..U32_LEN].copy_from_slice(&valid_bits.to_le_bytes());
    Ok(CommandResponse::Data(U32_LEN + data_len))
}

#[cfg(feature = "device-ownership-transfer")]
async fn execute_authorized_dot<H, Alloc>(
    commands: &H,
    alloc: &Alloc,
    payload: &[u8],
    output: &mut [u8],
) -> CaliptraCmdResult<CommandResponse>
where
    H: CaliptraCmdHandler,
    Alloc: ScratchAlloc,
{
    let (subcommand, payload) = split_id(payload)?;
    match subcommand {
        value if value == CommandId::MC_DOT_ENABLE.0 => {
            require_empty(payload)?;
            commands.dot_enable().await?;
            Ok(CommandResponse::ResetRequired)
        }
        value if value == CommandId::MC_DOT_LOCK.0 => {
            let request = DotLockPayload::ref_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands.dot_lock(alloc, request).await?;
            Ok(CommandResponse::ResetRequired)
        }
        value if value == CommandId::MC_DOT_DISABLE.0 => {
            let request = DotDisablePayload::ref_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands.dot_disable(alloc, request).await?;
            Ok(CommandResponse::ResetRequired)
        }
        value if value == CommandId::MC_DOT_ROTATE.0 => {
            let request = DotRotatePayload::read_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands.dot_rotate(alloc, &request).await?;
            Ok(CommandResponse::ResetRequired)
        }
        value if value == CommandId::MC_GET_DOT_BACKUP_BLOB.0 => {
            require_empty(payload)?;
            let blob = output
                .get_mut(..DOT_BLOB_SIZE)
                .ok_or(CaliptraCompletionCode::InsufficientResources)?;
            let blob = <&mut [u8; DOT_BLOB_SIZE]>::try_from(blob)
                .map_err(|_| CaliptraCompletionCode::InsufficientResources)?;
            commands.dot_get_backup_blob(alloc, blob).await?;
            Ok(CommandResponse::Data(DOT_BLOB_SIZE))
        }
        _ => Err(CaliptraCompletionCode::InvalidParameter),
    }
}

#[cfg(not(feature = "device-ownership-transfer"))]
async fn execute_authorized_dot<H, Alloc>(
    _commands: &H,
    _alloc: &Alloc,
    _payload: &[u8],
    _output: &mut [u8],
) -> CaliptraCmdResult<CommandResponse>
where
    H: CaliptraCmdHandler,
    Alloc: ScratchAlloc,
{
    Err(CaliptraCompletionCode::UnsupportedOperation)
}

#[cfg(feature = "ocp-lock")]
async fn execute_authorized_ocp_lock<H, Alloc>(
    commands: &H,
    alloc: &Alloc,
    payload: &[u8],
) -> CaliptraCmdResult<CommandResponse>
where
    H: CaliptraCmdHandler,
    Alloc: ScratchAlloc,
{
    let (subcommand, payload) = split_id(payload)?;
    match subcommand {
        value if value == CommandId::MC_OCP_LOCK_PROGRAM_HEK.0 => {
            let payload = WireCommandId::ref_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands
                .ocp_lock_program_hek(alloc, payload.value.get())
                .await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_OCP_LOCK_ZERO_HEK.0 => {
            let payload = WireCommandId::ref_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands
                .ocp_lock_zero_hek(alloc, payload.value.get())
                .await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_OCP_LOCK_ROTATE_HEK.0 => {
            let payload = WireCommandId::ref_from_bytes(payload)
                .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
            commands
                .ocp_lock_rotate_hek(alloc, payload.value.get())
                .await?;
            Ok(CommandResponse::Empty)
        }
        value if value == CommandId::MC_OCP_LOCK_SET_PERMA_HEK.0 => {
            require_empty(payload)?;
            commands.ocp_lock_set_perma_hek().await?;
            Ok(CommandResponse::Empty)
        }
        _ => Err(CaliptraCompletionCode::InvalidParameter),
    }
}

#[cfg(not(feature = "ocp-lock"))]
async fn execute_authorized_ocp_lock<H, Alloc>(
    _commands: &H,
    _alloc: &Alloc,
    _payload: &[u8],
) -> CaliptraCmdResult<CommandResponse>
where
    H: CaliptraCmdHandler,
    Alloc: ScratchAlloc,
{
    Err(CaliptraCompletionCode::UnsupportedOperation)
}

fn split_authorized_request(
    request: &[u8],
    payload_len: usize,
) -> CaliptraCmdResult<AuthorizedRequest<'_>> {
    let expected_len = payload_len
        .checked_add(AUTHORIZATION_TRAILER_LEN)
        .ok_or(CaliptraCompletionCode::InvalidPayloadSize)?;
    if request.len() != expected_len {
        return Err(CaliptraCompletionCode::InvalidPayloadSize);
    }

    let (payload, authorization) = request.split_at(payload_len);
    let authorization = AuthorizationBlock::ref_from_bytes(authorization)
        .map_err(|_| CaliptraCompletionCode::InvalidParameter)?;
    Ok(AuthorizedRequest {
        payload,
        authorization,
    })
}

fn split_id(request: &[u8]) -> CaliptraCmdResult<(u32, &[u8])> {
    let (id, request) = WireCommandId::ref_from_prefix(request)
        .map_err(|_| CaliptraCompletionCode::InvalidPayloadSize)?;
    Ok((id.value.get(), request))
}

#[cfg(any(feature = "device-ownership-transfer", feature = "ocp-lock"))]
fn require_empty(payload: &[u8]) -> CaliptraCmdResult<()> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(CaliptraCompletionCode::InvalidPayloadSize)
    }
}

#[cfg(feature = "device-ownership-transfer")]
fn write_output(output: &mut [u8], data: &[u8]) -> CaliptraCmdResult<CommandResponse> {
    output
        .get_mut(..data.len())
        .ok_or(CaliptraCompletionCode::InsufficientResources)?
        .copy_from_slice(data);
    Ok(CommandResponse::Data(data.len()))
}
