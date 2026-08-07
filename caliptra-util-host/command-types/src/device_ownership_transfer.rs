// Licensed under the Apache-2.0 license

//! Device Ownership Transfer command types.

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use caliptra_mcu_mbox_common::messages::CommandId;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub use caliptra_mcu_mbox_common::messages::{
    DotDisablePayload as DotDisableRequest, DotLockPayload as DotLockRequest,
    DotUnlockPayload as DotUnlockRequest, HybridSignature, AUTH_CMD_NONCE_LEN, DOT_BLOB_SIZE,
    DOT_ECC_PUBLIC_KEY_COORD_SIZE, DOT_KEY_HASH_SIZE, DOT_MLDSA_PUBLIC_KEY_SIZE,
};

pub const MC_DOT_LOCK_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_LOCK.0;
pub const MC_DOT_DISABLE_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_DISABLE.0;
pub const MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_UNLOCK_CHALLENGE.0;
pub const MC_DOT_UNLOCK_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_UNLOCK.0;
pub const MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID: u32 = CommandId::MC_GET_DOT_BACKUP_BLOB.0;

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotTransitionResponse {
    pub common: CommonResponse,
    pub reset_required: u32,
}

impl CommandResponse for DotTransitionResponse {}

impl CommandRequest for DotLockRequest {
    type Response = DotTransitionResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::DotLock;
}

impl CommandRequest for DotDisableRequest {
    type Response = DotTransitionResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::DotDisable;
}

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotUnlockChallengeRequest;

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotUnlockChallengeResponse {
    pub common: CommonResponse,
    pub challenge: [u8; AUTH_CMD_NONCE_LEN],
}

impl Default for DotUnlockChallengeResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse::default(),
            challenge: [0; AUTH_CMD_NONCE_LEN],
        }
    }
}

impl CommandRequest for DotUnlockChallengeRequest {
    type Response = DotUnlockChallengeResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::DotUnlockChallenge;
}

impl CommandResponse for DotUnlockChallengeResponse {}

impl CommandRequest for DotUnlockRequest {
    type Response = DotTransitionResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::DotUnlock;
}

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetDotBackupBlobRequest;

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetDotBackupBlobResponse {
    pub common: CommonResponse,
    pub blob: [u8; DOT_BLOB_SIZE],
}

impl Default for GetDotBackupBlobResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse::default(),
            blob: [0; DOT_BLOB_SIZE],
        }
    }
}

impl CommandRequest for GetDotBackupBlobRequest {
    type Response = GetDotBackupBlobResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetDotBackupBlob;
}

impl CommandResponse for GetDotBackupBlobResponse {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_ids_match_mcu_mailbox_commands() {
        assert_eq!(MC_DOT_LOCK_CANONICAL_CMD_ID, CommandId::MC_DOT_LOCK.0);
        assert_eq!(MC_DOT_DISABLE_CANONICAL_CMD_ID, CommandId::MC_DOT_DISABLE.0);
        assert_eq!(
            MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID,
            CommandId::MC_DOT_UNLOCK_CHALLENGE.0
        );
        assert_eq!(MC_DOT_UNLOCK_CANONICAL_CMD_ID, CommandId::MC_DOT_UNLOCK.0);
        assert_eq!(
            MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID,
            CommandId::MC_GET_DOT_BACKUP_BLOB.0
        );
    }
}
