// Licensed under the Apache-2.0 license

//! Device Ownership Transfer commands for mailbox transport.

use super::checksum::calc_checksum;
use super::command_traits::{
    ExternalCommandMetadata, FromInternalRequest, ToInternalResponse, VariableSizeBytes,
};
use caliptra_mcu_core_util_host_command_types::device_ownership_transfer::{
    DotChallengeResponse, DotDisableRequest, DotLockRequest, DotOverrideChallengeRequest,
    DotOverrideRequest, DotRecoveryRequest, DotRotateRequest, DotStatus, DotStatusRequest,
    DotStatusResponse, DotTransitionResponse, DotUnlockChallengeRequest, DotUnlockRequest,
    GetDotBackupBlobRequest, GetDotBackupBlobResponse, AUTH_CMD_NONCE_LEN, DOT_BLOB_SIZE,
    MC_DOT_DISABLE_CANONICAL_CMD_ID, MC_DOT_LOCK_CANONICAL_CMD_ID,
    MC_DOT_OVERRIDE_CANONICAL_CMD_ID, MC_DOT_OVERRIDE_CHALLENGE_CANONICAL_CMD_ID,
    MC_DOT_RECOVERY_CANONICAL_CMD_ID, MC_DOT_ROTATE_CANONICAL_CMD_ID,
    MC_DOT_STATUS_CANONICAL_CMD_ID, MC_DOT_UNLOCK_CANONICAL_CMD_ID,
    MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID, MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID,
};
use caliptra_mcu_core_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::define_command;

macro_rules! define_dot_request {
    ($external:ident, $internal:ty, $subcommand:expr) => {
        #[repr(C)]
        #[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
        pub struct $external {
            pub chksum: u32,
            pub subcommand: u32,
            pub request: $internal,
        }

        impl FromInternalRequest<$internal> for $external {
            fn from_internal(internal: &$internal, command_code: u32) -> Self {
                let mut external = Self {
                    chksum: 0,
                    subcommand: $subcommand,
                    request: internal.clone(),
                };
                external.chksum = calc_checksum(command_code, &external.as_bytes()[4..]);
                external
            }
        }
    };
}

define_dot_request!(
    ExtCmdDotLockRequest,
    DotLockRequest,
    MC_DOT_LOCK_CANONICAL_CMD_ID
);
define_dot_request!(
    ExtCmdDotDisableRequest,
    DotDisableRequest,
    MC_DOT_DISABLE_CANONICAL_CMD_ID
);
define_dot_request!(
    ExtCmdDotRotateRequest,
    DotRotateRequest,
    MC_DOT_ROTATE_CANONICAL_CMD_ID
);
define_dot_request!(
    ExtCmdDotUnlockChallengeRequest,
    DotUnlockChallengeRequest,
    MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID
);
define_dot_request!(
    ExtCmdDotUnlockRequest,
    DotUnlockRequest,
    MC_DOT_UNLOCK_CANONICAL_CMD_ID
);
define_dot_request!(
    ExtCmdGetDotBackupBlobRequest,
    GetDotBackupBlobRequest,
    MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID
);
define_dot_request!(
    ExtCmdDotStatusRequest,
    DotStatusRequest,
    MC_DOT_STATUS_CANONICAL_CMD_ID
);
define_dot_request!(
    ExtCmdDotRecoveryRequest,
    DotRecoveryRequest,
    MC_DOT_RECOVERY_CANONICAL_CMD_ID
);
define_dot_request!(
    ExtCmdDotOverrideChallengeRequest,
    DotOverrideChallengeRequest,
    MC_DOT_OVERRIDE_CHALLENGE_CANONICAL_CMD_ID
);
define_dot_request!(
    ExtCmdDotOverrideRequest,
    DotOverrideRequest,
    MC_DOT_OVERRIDE_CANONICAL_CMD_ID
);

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDotTransitionResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub reset_required: u32,
}

impl ToInternalResponse<DotTransitionResponse> for ExtCmdDotTransitionResponse {
    fn to_internal(&self) -> DotTransitionResponse {
        DotTransitionResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            reset_required: self.reset_required,
        }
    }
}

impl VariableSizeBytes for ExtCmdDotTransitionResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDotChallengeResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub challenge: [u8; AUTH_CMD_NONCE_LEN],
}

impl Default for ExtCmdDotChallengeResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            challenge: [0; AUTH_CMD_NONCE_LEN],
        }
    }
}

impl ToInternalResponse<DotChallengeResponse> for ExtCmdDotChallengeResponse {
    fn to_internal(&self) -> DotChallengeResponse {
        DotChallengeResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            challenge: self.challenge,
        }
    }
}

impl VariableSizeBytes for ExtCmdDotChallengeResponse {}

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdDotStatusResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub status: DotStatus,
}

impl ToInternalResponse<DotStatusResponse> for ExtCmdDotStatusResponse {
    fn to_internal(&self) -> DotStatusResponse {
        DotStatusResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            status: self.status,
        }
    }
}

impl VariableSizeBytes for ExtCmdDotStatusResponse {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetDotBackupBlobResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub blob: [u8; DOT_BLOB_SIZE],
}

impl Default for ExtCmdGetDotBackupBlobResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            blob: [0; DOT_BLOB_SIZE],
        }
    }
}

impl ToInternalResponse<GetDotBackupBlobResponse> for ExtCmdGetDotBackupBlobResponse {
    fn to_internal(&self) -> GetDotBackupBlobResponse {
        GetDotBackupBlobResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            blob: self.blob,
        }
    }
}

impl VariableSizeBytes for ExtCmdGetDotBackupBlobResponse {}

define_command!(
    DotLockCmd,
    0x0000_0011,
    DotLockRequest,
    DotTransitionResponse,
    ExtCmdDotLockRequest,
    ExtCmdDotTransitionResponse
);
define_command!(
    DotDisableCmd,
    0x0000_0011,
    DotDisableRequest,
    DotTransitionResponse,
    ExtCmdDotDisableRequest,
    ExtCmdDotTransitionResponse
);
define_command!(
    DotRotateCmd,
    0x0000_0011,
    DotRotateRequest,
    DotTransitionResponse,
    ExtCmdDotRotateRequest,
    ExtCmdDotTransitionResponse
);
define_command!(
    DotUnlockChallengeCmd,
    0x0000_0011,
    DotUnlockChallengeRequest,
    DotChallengeResponse,
    ExtCmdDotUnlockChallengeRequest,
    ExtCmdDotChallengeResponse
);
define_command!(
    DotUnlockCmd,
    0x0000_0011,
    DotUnlockRequest,
    DotTransitionResponse,
    ExtCmdDotUnlockRequest,
    ExtCmdDotTransitionResponse
);
define_command!(
    GetDotBackupBlobCmd,
    0x0000_0011,
    GetDotBackupBlobRequest,
    GetDotBackupBlobResponse,
    ExtCmdGetDotBackupBlobRequest,
    ExtCmdGetDotBackupBlobResponse
);
define_command!(
    DotStatusCmd,
    0x0000_0011,
    DotStatusRequest,
    DotStatusResponse,
    ExtCmdDotStatusRequest,
    ExtCmdDotStatusResponse
);
define_command!(
    DotRecoveryCmd,
    0x0000_0011,
    DotRecoveryRequest,
    DotTransitionResponse,
    ExtCmdDotRecoveryRequest,
    ExtCmdDotTransitionResponse
);
define_command!(
    DotOverrideChallengeCmd,
    0x0000_0011,
    DotOverrideChallengeRequest,
    DotChallengeResponse,
    ExtCmdDotOverrideChallengeRequest,
    ExtCmdDotChallengeResponse
);
define_command!(
    DotOverrideCmd,
    0x0000_0011,
    DotOverrideRequest,
    DotTransitionResponse,
    ExtCmdDotOverrideRequest,
    ExtCmdDotTransitionResponse
);

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::super::dispatch::get_command_handler;
    use super::super::transport::{MailboxDriver, MailboxError};
    use super::*;
    use alloc::vec::Vec;
    use caliptra_mcu_core_util_host_command_types::device_ownership_transfer::DOT_FAMILY_ID;
    use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;

    struct RecordingMailbox {
        external_cmd: u32,
        request: Vec<u8>,
        response: Vec<u8>,
    }

    impl MailboxDriver for RecordingMailbox {
        fn send_command(
            &mut self,
            external_cmd: u32,
            payload: &[u8],
        ) -> Result<&[u8], MailboxError> {
            self.external_cmd = external_cmd;
            self.request.clear();
            self.request.extend_from_slice(payload);
            Ok(&self.response)
        }

        fn is_ready(&self) -> bool {
            true
        }

        fn connect(&mut self) -> Result<(), MailboxError> {
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), MailboxError> {
            Ok(())
        }
    }

    fn assert_request_wire<Internal, External>(internal: &Internal, subcommand: u32)
    where
        Internal: IntoBytes + Immutable,
        External: FromInternalRequest<Internal> + IntoBytes + Immutable,
    {
        let external = External::from_internal(internal, DOT_FAMILY_ID);
        let bytes = external.as_bytes();

        assert_eq!(bytes.len(), 8 + internal.as_bytes().len());
        assert_eq!(&bytes[4..8], &subcommand.to_le_bytes());
        assert_eq!(&bytes[8..], internal.as_bytes());

        let checksum = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(checksum, calc_checksum(DOT_FAMILY_ID, &bytes[4..]));
    }

    #[test]
    fn all_requests_use_the_dot_family_envelope() {
        let mut lock = DotLockRequest::default();
        lock.cak.fill(0x11);
        lock.lak_hash.fill(0x22);
        lock.authorization.nonce.fill(0x33);
        lock.authorization.ecc_pub_x.fill(0x44);
        lock.authorization.ecc_pub_y.fill(0x55);
        lock.authorization.mldsa_pub.fill(0x66);
        lock.authorization.signature.ecc_sig_r.fill(0x77);
        lock.authorization.signature.ecc_sig_s.fill(0x88);
        lock.authorization.signature.mldsa_sig.fill(0x99);

        assert_request_wire::<_, ExtCmdDotLockRequest>(&lock, MC_DOT_LOCK_CANONICAL_CMD_ID);
        assert_request_wire::<_, ExtCmdDotDisableRequest>(
            &DotDisableRequest::default(),
            MC_DOT_DISABLE_CANONICAL_CMD_ID,
        );
        assert_request_wire::<_, ExtCmdDotRotateRequest>(
            &DotRotateRequest::default(),
            MC_DOT_ROTATE_CANONICAL_CMD_ID,
        );
        assert_request_wire::<_, ExtCmdDotUnlockChallengeRequest>(
            &DotUnlockChallengeRequest,
            MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID,
        );
        assert_request_wire::<_, ExtCmdDotUnlockRequest>(
            &DotUnlockRequest::default(),
            MC_DOT_UNLOCK_CANONICAL_CMD_ID,
        );
        assert_request_wire::<_, ExtCmdGetDotBackupBlobRequest>(
            &GetDotBackupBlobRequest::default(),
            MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID,
        );
        assert_request_wire::<_, ExtCmdDotStatusRequest>(
            &DotStatusRequest,
            MC_DOT_STATUS_CANONICAL_CMD_ID,
        );
        assert_request_wire::<_, ExtCmdDotRecoveryRequest>(
            &DotRecoveryRequest::default(),
            MC_DOT_RECOVERY_CANONICAL_CMD_ID,
        );
        assert_request_wire::<_, ExtCmdDotOverrideChallengeRequest>(
            &DotOverrideChallengeRequest::default(),
            MC_DOT_OVERRIDE_CHALLENGE_CANONICAL_CMD_ID,
        );
        assert_request_wire::<_, ExtCmdDotOverrideRequest>(
            &DotOverrideRequest::default(),
            MC_DOT_OVERRIDE_CANONICAL_CMD_ID,
        );
    }

    #[test]
    fn responses_convert_to_transport_neutral_types() {
        let transition = ExtCmdDotTransitionResponse {
            chksum: 0,
            fips_status: 7,
            reset_required: 1,
        }
        .to_internal();
        assert_eq!(transition.common.fips_status, 7);
        assert_eq!(transition.reset_required, 1);

        let challenge = ExtCmdDotChallengeResponse {
            chksum: 0,
            fips_status: 8,
            challenge: [0xA5; AUTH_CMD_NONCE_LEN],
        }
        .to_internal();
        assert_eq!(challenge.common.fips_status, 8);
        assert_eq!(challenge.challenge, [0xA5; AUTH_CMD_NONCE_LEN]);

        let status = ExtCmdDotStatusResponse {
            chksum: 0,
            fips_status: 9,
            status: DotStatus {
                enabled: 1,
                locked: 1,
                burned: 3,
            },
        }
        .to_internal();
        assert_eq!(status.common.fips_status, 9);
        assert_eq!(status.status.enabled, 1);
        assert_eq!(status.status.locked, 1);
        assert_eq!(status.status.burned, 3);

        let backup = ExtCmdGetDotBackupBlobResponse {
            chksum: 0,
            fips_status: 10,
            blob: [0x5A; DOT_BLOB_SIZE],
        }
        .to_internal();
        assert_eq!(backup.common.fips_status, 10);
        assert_eq!(backup.blob, [0x5A; DOT_BLOB_SIZE]);
    }

    #[test]
    fn dispatched_handler_sends_family_frame_and_decodes_response() {
        let fips_status = 0x1234_5678u32;
        let reset_required = 1u32;
        let mut response_payload = Vec::new();
        response_payload.extend_from_slice(&fips_status.to_le_bytes());
        response_payload.extend_from_slice(&reset_required.to_le_bytes());

        let mut response = Vec::new();
        response.extend_from_slice(&calc_checksum(0, &response_payload).to_le_bytes());
        response.extend_from_slice(&response_payload);

        let mut mailbox = RecordingMailbox {
            external_cmd: 0,
            request: Vec::new(),
            response,
        };
        let mut request = DotLockRequest::default();
        request.cak.fill(0xA1);
        request.authorization.nonce.fill(0xB2);
        request.authorization.signature.mldsa_sig.fill(0xC3);

        let handler = get_command_handler(CaliptraCommandId::DotLock as u32).unwrap();
        let mut response_buffer = [0u8; core::mem::size_of::<DotTransitionResponse>()];
        let response_len = handler(request.as_bytes(), &mut mailbox, &mut response_buffer).unwrap();

        assert_eq!(mailbox.external_cmd, DOT_FAMILY_ID);
        assert_eq!(
            &mailbox.request[4..8],
            &MC_DOT_LOCK_CANONICAL_CMD_ID.to_le_bytes()
        );
        assert_eq!(&mailbox.request[8..], request.as_bytes());
        assert_eq!(
            u32::from_le_bytes(mailbox.request[..4].try_into().unwrap()),
            calc_checksum(DOT_FAMILY_ID, &mailbox.request[4..])
        );

        let internal_response =
            DotTransitionResponse::read_from_bytes(&response_buffer[..response_len]).unwrap();
        assert_eq!(internal_response.common.fips_status, fips_status);
        assert_eq!(internal_response.reset_required, reset_required);
    }
}
