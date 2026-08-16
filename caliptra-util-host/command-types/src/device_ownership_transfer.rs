// Licensed under the Apache-2.0 license

//! Device Ownership Transfer command types.

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use caliptra_mcu_mbox_common::messages::CommandId;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub use caliptra_mcu_mbox_common::messages::{
    DotOverrideChallengePayload as DotOverrideChallengeRequest,
    DotOverridePayload as DotOverrideRequest, DotStatus, DotUnlockPayload as DotUnlockRequest,
    HybridSignature, AUTH_CMD_NONCE_LEN, DOT_BLOB_SIZE, DOT_ECC_PUBLIC_KEY_COORD_SIZE,
    DOT_KEY_HASH_SIZE, DOT_MLDSA_PUBLIC_KEY_SIZE,
};

pub const DOT_FAMILY_ID: u32 = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0;
pub const MC_DOT_LOCK_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_LOCK.0;
pub const MC_DOT_DISABLE_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_DISABLE.0;
pub const MC_DOT_ROTATE_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_ROTATE.0;
pub const MC_DOT_STATUS_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_STATUS.0;
pub const MC_DOT_RECOVERY_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_RECOVERY.0;
pub const MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_UNLOCK_CHALLENGE.0;
pub const MC_DOT_UNLOCK_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_UNLOCK.0;
pub const MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID: u32 = CommandId::MC_GET_DOT_BACKUP_BLOB.0;
pub const MC_DOT_OVERRIDE_CHALLENGE_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_OVERRIDE_CHALLENGE.0;
pub const MC_DOT_OVERRIDE_CANONICAL_CMD_ID: u32 = CommandId::MC_DOT_OVERRIDE.0;

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotAuthorizationTrailer {
    pub nonce: [u8; AUTH_CMD_NONCE_LEN],
    pub ecc_pub_x: [u8; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
    pub ecc_pub_y: [u8; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
    pub mldsa_pub: [u8; DOT_MLDSA_PUBLIC_KEY_SIZE],
    pub signature: HybridSignature,
}

impl Default for DotAuthorizationTrailer {
    fn default() -> Self {
        Self {
            nonce: [0; AUTH_CMD_NONCE_LEN],
            ecc_pub_x: [0; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
            ecc_pub_y: [0; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
            mldsa_pub: [0; DOT_MLDSA_PUBLIC_KEY_SIZE],
            signature: HybridSignature::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotLockRequest {
    pub cak: [u8; DOT_KEY_HASH_SIZE],
    pub lak_hash: [u8; DOT_KEY_HASH_SIZE],
    pub authorization: DotAuthorizationTrailer,
}

impl Default for DotLockRequest {
    fn default() -> Self {
        Self {
            cak: [0; DOT_KEY_HASH_SIZE],
            lak_hash: [0; DOT_KEY_HASH_SIZE],
            authorization: DotAuthorizationTrailer::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotDisableRequest {
    pub lak_hash: [u8; DOT_KEY_HASH_SIZE],
    pub authorization: DotAuthorizationTrailer,
}

impl Default for DotDisableRequest {
    fn default() -> Self {
        Self {
            lak_hash: [0; DOT_KEY_HASH_SIZE],
            authorization: DotAuthorizationTrailer::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotRotateRequest {
    pub min_fuse_count: u32,
    pub cak: [u8; DOT_KEY_HASH_SIZE],
    pub lak_hash: [u8; DOT_KEY_HASH_SIZE],
    pub authorization: DotAuthorizationTrailer,
}

impl Default for DotRotateRequest {
    fn default() -> Self {
        Self {
            min_fuse_count: 0,
            cak: [0; DOT_KEY_HASH_SIZE],
            lak_hash: [0; DOT_KEY_HASH_SIZE],
            authorization: DotAuthorizationTrailer::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetDotBackupBlobRequest {
    pub authorization: DotAuthorizationTrailer,
}

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotUnlockChallengeRequest;

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotStatusRequest;

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotRecoveryRequest {
    pub blob: [u8; DOT_BLOB_SIZE],
}

impl Default for DotRecoveryRequest {
    fn default() -> Self {
        Self {
            blob: [0; DOT_BLOB_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotTransitionResponse {
    pub common: CommonResponse,
    pub reset_required: u32,
}

impl CommandResponse for DotTransitionResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotChallengeResponse {
    pub common: CommonResponse,
    pub challenge: [u8; AUTH_CMD_NONCE_LEN],
}

impl Default for DotChallengeResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse::default(),
            challenge: [0; AUTH_CMD_NONCE_LEN],
        }
    }
}

impl CommandResponse for DotChallengeResponse {}

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct DotStatusResponse {
    pub common: CommonResponse,
    pub status: DotStatus,
}

impl CommandResponse for DotStatusResponse {}

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

impl CommandResponse for GetDotBackupBlobResponse {}

macro_rules! command_request {
    ($request:ty, $response:ty, $command:ident) => {
        impl CommandRequest for $request {
            type Response = $response;
            const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::$command;
        }
    };
}

command_request!(DotLockRequest, DotTransitionResponse, DotLock);
command_request!(DotDisableRequest, DotTransitionResponse, DotDisable);
command_request!(DotRotateRequest, DotTransitionResponse, DotRotate);
command_request!(
    DotUnlockChallengeRequest,
    DotChallengeResponse,
    DotUnlockChallenge
);
command_request!(DotUnlockRequest, DotTransitionResponse, DotUnlock);
command_request!(
    GetDotBackupBlobRequest,
    GetDotBackupBlobResponse,
    GetDotBackupBlob
);
command_request!(DotStatusRequest, DotStatusResponse, DotStatus);
command_request!(DotRecoveryRequest, DotTransitionResponse, DotRecovery);
command_request!(
    DotOverrideChallengeRequest,
    DotChallengeResponse,
    DotOverrideChallenge
);
command_request!(DotOverrideRequest, DotTransitionResponse, DotOverride);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_ids_match_mcu_mailbox_commands() {
        assert_eq!(MC_DOT_LOCK_CANONICAL_CMD_ID, CommandId::MC_DOT_LOCK.0);
        assert_eq!(MC_DOT_DISABLE_CANONICAL_CMD_ID, CommandId::MC_DOT_DISABLE.0);
        assert_eq!(MC_DOT_ROTATE_CANONICAL_CMD_ID, CommandId::MC_DOT_ROTATE.0);
        assert_eq!(
            MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID,
            CommandId::MC_DOT_UNLOCK_CHALLENGE.0
        );
        assert_eq!(MC_DOT_UNLOCK_CANONICAL_CMD_ID, CommandId::MC_DOT_UNLOCK.0);
        assert_eq!(MC_DOT_STATUS_CANONICAL_CMD_ID, CommandId::MC_DOT_STATUS.0);
        assert_eq!(
            MC_DOT_RECOVERY_CANONICAL_CMD_ID,
            CommandId::MC_DOT_RECOVERY.0
        );
        assert_eq!(
            MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID,
            CommandId::MC_GET_DOT_BACKUP_BLOB.0
        );
        assert_eq!(
            MC_DOT_OVERRIDE_CHALLENGE_CANONICAL_CMD_ID,
            CommandId::MC_DOT_OVERRIDE_CHALLENGE.0
        );
        assert_eq!(
            MC_DOT_OVERRIDE_CANONICAL_CMD_ID,
            CommandId::MC_DOT_OVERRIDE.0
        );
        assert_eq!(DOT_FAMILY_ID, CommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0);
    }
}
