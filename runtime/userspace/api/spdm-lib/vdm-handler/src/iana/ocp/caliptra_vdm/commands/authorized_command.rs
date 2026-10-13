// Licensed under the Apache-2.0 license

//! AUTHORIZED_COMMAND (0x12) transport adapter.

use crate::iana::ocp::caliptra_vdm::CaliptraVdmAuthorization;
use caliptra_mcu_common_commands::command::{
    execute_authorized, CommandPolicy, CommandResponse, MAX_AUTHORIZED_REQUEST_LEN,
};
use caliptra_mcu_common_commands::CaliptraCmdHandler;
use caliptra_mcu_mbox_common::messages::CommandId;
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;

pub(in crate::iana::ocp::caliptra_vdm) const MAX_REQUEST_LEN: usize = MAX_AUTHORIZED_REQUEST_LEN;

pub const GET_AUTH_CHALLENGE_CMD_ID: u32 = CommandId::MC_GET_AUTH_CMD_CHALLENGE.0;
pub const PROVISION_VENDOR_PK_HASH_CMD_ID: u32 = CommandId::MC_PROVISION_VENDOR_PK_HASH.0;
pub const PROVISION_OWNER_PK_HASH_CMD_ID: u32 = CommandId::MC_PROVISION_OWNER_PK_HASH.0;
pub const INCREASE_MIN_SVN_CMD_ID: u32 = CommandId::MC_FUSE_INCREASE_MIN_SVN.0;
pub const FE_PROG_CMD_ID: u32 = CommandId::MC_FE_PROG.0;
pub const REVOKE_VENDOR_PUB_KEY_CMD_ID: u32 = CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY.0;
pub const REVOKE_VENDOR_PK_HASH_CMD_ID: u32 = CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH.0;
pub const FUSE_LOCK_PARTITION_CMD_ID: u32 = CommandId::MC_FUSE_LOCK_PARTITION.0;
pub const ZEROIZE_UDS_FE_AND_ENTER_RMA_CMD_ID: u32 = CommandId::MC_ZEROIZE_UDS_FE_AND_ENTER_RMA.0;
pub const DEVICE_OWNERSHIP_TRANSFER_CMD_ID: u32 = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0;
pub const DOT_ENABLE_CMD_ID: u32 = CommandId::MC_DOT_ENABLE.0;
pub const DOT_LOCK_CMD_ID: u32 = CommandId::MC_DOT_LOCK.0;
pub const DOT_DISABLE_CMD_ID: u32 = CommandId::MC_DOT_DISABLE.0;
pub const DOT_ROTATE_CMD_ID: u32 = CommandId::MC_DOT_ROTATE.0;
pub const GET_DOT_BACKUP_BLOB_CMD_ID: u32 = CommandId::MC_GET_DOT_BACKUP_BLOB.0;
#[cfg(feature = "ocp-lock")]
pub const OCP_LOCK_CMD_ID: u32 = CommandId::MC_OCP_LOCK.0;
#[cfg(feature = "ocp-lock")]
pub const OCP_LOCK_PROGRAM_HEK_CMD_ID: u32 = CommandId::MC_OCP_LOCK_PROGRAM_HEK.0;
#[cfg(feature = "ocp-lock")]
pub const OCP_LOCK_ZERO_HEK_CMD_ID: u32 = CommandId::MC_OCP_LOCK_ZERO_HEK.0;
#[cfg(feature = "ocp-lock")]
pub const OCP_LOCK_ROTATE_HEK_CMD_ID: u32 = CommandId::MC_OCP_LOCK_ROTATE_HEK.0;
#[cfg(feature = "ocp-lock")]
pub const OCP_LOCK_SET_PERMA_HEK_CMD_ID: u32 = CommandId::MC_OCP_LOCK_SET_PERMA_HEK.0;

pub(crate) async fn handle<H, Auth, Alloc>(
    commands: &H,
    authorizer: &Auth,
    request: &[u8],
    scratch: &Alloc,
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    Auth: CaliptraVdmAuthorization,
    Alloc: SpdmPalAlloc,
{
    let Some((completion, response)) = output.split_first_mut() else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };
    match execute_authorized(
        commands,
        authorizer,
        scratch.allocator(),
        request,
        response,
        CommandPolicy::SPDM,
    )
    .await
    {
        Ok(CommandResponse::Data(len)) => {
            *completion = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1 + len)
        }
        Ok(CommandResponse::Empty | CommandResponse::ResetRequired) => {
            *completion = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1)
        }
        Err(error) => CaliptraVdmCmdResult::Error(super::map_common_completion(error)),
    }
}
