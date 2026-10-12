// Licensed under the Apache-2.0 license

//! Mailbox transport layer for authorized fuse commands
//!
//! Every command in this module uses `MC_AUTHORIZED_COMMAND` (`0x12`) as the
//! mailbox command and carries its canonical target ID in the payload.

use super::checksum::calc_checksum;
use super::command_traits::{
    ExternalCommandMetadata, FromInternalRequest, ToInternalResponse, VariableSizeBytes,
};
use caliptra_mcu_core_util_host_command_types::fuse::{
    FeProgRequest, FeProgResponse, FuseIncreaseMinSvnRequest, FuseIncreaseMinSvnResponse,
    FuseLockPartitionRequest, FuseLockPartitionResponse, FuseRevokeVendorPkHashRequest,
    FuseRevokeVendorPkHashResponse, FuseRevokeVendorPubKeyRequest, FuseRevokeVendorPubKeyResponse,
    GetAuthCmdChallengeRequest, GetAuthCmdChallengeResponse, OcpLockRotateHekRequest,
    OcpLockRotateHekResponse, OcpLockSetPermaHekRequest, OcpLockSetPermaHekResponse,
    ProvisionOwnerPkHashRequest, ProvisionOwnerPkHashResponse, ProvisionVendorPkHashRequest,
    ProvisionVendorPkHashResponse, AUTH_CMD_CHALLENGE_SIZE,
    MC_OCP_LOCK_ROTATE_HEK_CANONICAL_CMD_ID, MC_OCP_LOCK_SET_PERMA_HEK_CANONICAL_CMD_ID,
};
use caliptra_mcu_core_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::define_command;

// ============================================================================
// Get Authorization Command Challenge
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetAuthCmdChallengeRequest {
    pub chksum: u32,
    pub target: u32,
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetAuthCmdChallengeResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub reserved: u32,
    pub challenge: [u8; AUTH_CMD_CHALLENGE_SIZE],
}

impl Default for ExtCmdGetAuthCmdChallengeResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            reserved: 0,
            challenge: [0u8; AUTH_CMD_CHALLENGE_SIZE],
        }
    }
}

impl FromInternalRequest<GetAuthCmdChallengeRequest> for ExtCmdGetAuthCmdChallengeRequest {
    fn from_internal(_internal: &GetAuthCmdChallengeRequest, command_code: u32) -> Self {
        let target = caliptra_mcu_core_util_host_command_types::fuse::
            MC_GET_AUTH_CMD_CHALLENGE_CANONICAL_CMD_ID;
        Self {
            chksum: calc_checksum(command_code, &target.to_le_bytes()),
            target,
        }
    }
}

impl ToInternalResponse<GetAuthCmdChallengeResponse> for ExtCmdGetAuthCmdChallengeResponse {
    fn to_internal(&self) -> GetAuthCmdChallengeResponse {
        GetAuthCmdChallengeResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            reserved: self.reserved,
            challenge: self.challenge,
        }
    }
}

impl VariableSizeBytes for ExtCmdGetAuthCmdChallengeRequest {}
impl VariableSizeBytes for ExtCmdGetAuthCmdChallengeResponse {}

// ============================================================================
// Field Entropy Programming (FE_PROG)
// ============================================================================

#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdFeProgRequest {
    pub chksum: u32,
    pub target: u32,
    pub internal: FeProgRequest,
}

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdFeProgResponse {
    pub chksum: u32,
    pub fips_status: u32,
}

impl FromInternalRequest<FeProgRequest> for ExtCmdFeProgRequest {
    fn from_internal(internal: &FeProgRequest, command_code: u32) -> Self {
        let mut request = Self {
            chksum: 0,
            target: caliptra_mcu_core_util_host_command_types::fuse::MC_FE_PROG_CANONICAL_CMD_ID,
            internal: internal.clone(),
        };
        request.chksum = calc_checksum(command_code, &request.as_bytes()[4..]);
        request
    }
}

impl ToInternalResponse<FeProgResponse> for ExtCmdFeProgResponse {
    fn to_internal(&self) -> FeProgResponse {
        FeProgResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
        }
    }
}

impl VariableSizeBytes for ExtCmdFeProgRequest {}
impl VariableSizeBytes for ExtCmdFeProgResponse {}

// ============================================================================
// Command Metadata Definitions
// ============================================================================

define_command!(
    GetAuthCmdChallengeCmd,
    0x0000_0012,
    GetAuthCmdChallengeRequest,
    GetAuthCmdChallengeResponse,
    ExtCmdGetAuthCmdChallengeRequest,
    ExtCmdGetAuthCmdChallengeResponse
);

define_command!(
    FeProgCmd,
    0x0000_0012,
    FeProgRequest,
    FeProgResponse,
    ExtCmdFeProgRequest,
    ExtCmdFeProgResponse
);

macro_rules! define_authorized_fuse_mailbox_command {
    ($cmd:ident, $code:literal, $request:ident, $response:ident, $ext_request:ident, $ext_response:ident) => {
        #[repr(C)]
        #[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
        pub struct $ext_request {
            pub chksum: u32,
            pub target: u32,
            pub internal: $request,
        }

        #[repr(C)]
        #[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
        pub struct $ext_response {
            pub chksum: u32,
            pub fips_status: u32,
        }

        impl FromInternalRequest<$request> for $ext_request {
            fn from_internal(internal: &$request, command_code: u32) -> Self {
                let mut request = Self {
                    chksum: 0,
                    target: $code,
                    internal: internal.clone(),
                };
                request.chksum = calc_checksum(command_code, &request.as_bytes()[4..]);
                request
            }
        }

        impl ToInternalResponse<$response> for $ext_response {
            fn to_internal(&self) -> $response {
                $response {
                    common: CommonResponse {
                        fips_status: self.fips_status,
                    },
                }
            }
        }

        impl VariableSizeBytes for $ext_request {}
        impl VariableSizeBytes for $ext_response {}

        define_command!(
            $cmd,
            0x0000_0012,
            $request,
            $response,
            $ext_request,
            $ext_response
        );
    };
}

define_authorized_fuse_mailbox_command!(
    ProvisionVendorPkHashCmd,
    0x5056_504B,
    ProvisionVendorPkHashRequest,
    ProvisionVendorPkHashResponse,
    ExtCmdProvisionVendorPkHashRequest,
    ExtCmdProvisionVendorPkHashResponse
);
define_authorized_fuse_mailbox_command!(
    ProvisionOwnerPkHashCmd,
    0x504F_504B,
    ProvisionOwnerPkHashRequest,
    ProvisionOwnerPkHashResponse,
    ExtCmdProvisionOwnerPkHashRequest,
    ExtCmdProvisionOwnerPkHashResponse
);
define_authorized_fuse_mailbox_command!(
    FuseIncreaseMinSvnCmd,
    0x4D43_4D53,
    FuseIncreaseMinSvnRequest,
    FuseIncreaseMinSvnResponse,
    ExtCmdFuseIncreaseMinSvnRequest,
    ExtCmdFuseIncreaseMinSvnResponse
);
define_authorized_fuse_mailbox_command!(
    FuseRevokeVendorPubKeyCmd,
    0x4D52_564B,
    FuseRevokeVendorPubKeyRequest,
    FuseRevokeVendorPubKeyResponse,
    ExtCmdFuseRevokeVendorPubKeyRequest,
    ExtCmdFuseRevokeVendorPubKeyResponse
);
define_authorized_fuse_mailbox_command!(
    FuseRevokeVendorPkHashCmd,
    0x5256_4B48,
    FuseRevokeVendorPkHashRequest,
    FuseRevokeVendorPkHashResponse,
    ExtCmdFuseRevokeVendorPkHashRequest,
    ExtCmdFuseRevokeVendorPkHashResponse
);
define_authorized_fuse_mailbox_command!(
    FuseLockPartitionCmd,
    0x4946_504B,
    FuseLockPartitionRequest,
    FuseLockPartitionResponse,
    ExtCmdFuseLockPartitionRequest,
    ExtCmdFuseLockPartitionResponse
);
macro_rules! define_ocp_lock_mailbox_command {
    ($cmd:ident, $subcommand:expr, $request:ty, $response:ident, $ext_request:ident, $ext_response:ident) => {
        #[repr(C)]
        #[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
        pub struct $ext_request {
            pub chksum: u32,
            pub family: u32,
            pub subcommand: u32,
            pub internal: $request,
        }

        #[repr(C)]
        #[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
        pub struct $ext_response {
            pub chksum: u32,
            pub fips_status: u32,
        }

        impl FromInternalRequest<$request> for $ext_request {
            fn from_internal(internal: &$request, command_code: u32) -> Self {
                let mut external = Self {
                    chksum: 0,
                    family: caliptra_mcu_core_util_host_command_types::fuse::OCP_LOCK_FAMILY_ID,
                    subcommand: $subcommand,
                    internal: internal.clone(),
                };
                external.chksum = calc_checksum(command_code, &external.as_bytes()[4..]);
                external
            }
        }

        impl ToInternalResponse<$response> for $ext_response {
            fn to_internal(&self) -> $response {
                $response {
                    common: CommonResponse {
                        fips_status: self.fips_status,
                    },
                }
            }
        }

        impl VariableSizeBytes for $ext_request {}
        impl VariableSizeBytes for $ext_response {}

        define_command!(
            $cmd,
            0x0000_0012,
            $request,
            $response,
            $ext_request,
            $ext_response
        );
    };
}

define_ocp_lock_mailbox_command!(
    OcpLockRotateHekCmd,
    MC_OCP_LOCK_ROTATE_HEK_CANONICAL_CMD_ID,
    OcpLockRotateHekRequest,
    OcpLockRotateHekResponse,
    ExtCmdOcpLockRotateHekRequest,
    ExtCmdOcpLockRotateHekResponse
);
define_ocp_lock_mailbox_command!(
    OcpLockSetPermaHekCmd,
    MC_OCP_LOCK_SET_PERMA_HEK_CANONICAL_CMD_ID,
    OcpLockSetPermaHekRequest,
    OcpLockSetPermaHekResponse,
    ExtCmdOcpLockSetPermaHekRequest,
    ExtCmdOcpLockSetPermaHekResponse
);

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_mcu_core_util_host_command_types::fuse::{
        MC_FE_PROG_CANONICAL_CMD_ID, MC_GET_AUTH_CMD_CHALLENGE_CANONICAL_CMD_ID,
        MC_PROVISION_OWNER_PK_HASH_CANONICAL_CMD_ID, OCP_LOCK_FAMILY_ID,
    };

    fn assert_checksum(bytes: &[u8]) {
        let checksum = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(checksum, calc_checksum(0x12, &bytes[4..]));
    }

    #[test]
    fn authorized_requests_use_command_0x12_and_target_prefix() {
        let challenge =
            ExtCmdGetAuthCmdChallengeRequest::from_internal(&GetAuthCmdChallengeRequest, 0x12);
        assert_eq!(
            &challenge.as_bytes()[4..],
            &MC_GET_AUTH_CMD_CHALLENGE_CANONICAL_CMD_ID.to_le_bytes()
        );
        assert_checksum(challenge.as_bytes());

        let fe_prog = ExtCmdFeProgRequest::from_internal(&FeProgRequest::default(), 0x12);
        assert_eq!(
            &fe_prog.as_bytes()[4..8],
            &MC_FE_PROG_CANONICAL_CMD_ID.to_le_bytes()
        );
        assert_checksum(fe_prog.as_bytes());

        let owner = ExtCmdProvisionOwnerPkHashRequest::from_internal(
            &ProvisionOwnerPkHashRequest::default(),
            0x12,
        );
        assert_eq!(
            &owner.as_bytes()[4..8],
            &MC_PROVISION_OWNER_PK_HASH_CANONICAL_CMD_ID.to_le_bytes()
        );
        assert_checksum(owner.as_bytes());
    }

    #[test]
    fn authorized_ocp_lock_requests_carry_family_then_subcommand() {
        let rotate =
            ExtCmdOcpLockRotateHekRequest::from_internal(&OcpLockRotateHekRequest::default(), 0x12);
        assert_eq!(&rotate.as_bytes()[4..8], &OCP_LOCK_FAMILY_ID.to_le_bytes());
        assert_eq!(
            &rotate.as_bytes()[8..12],
            &MC_OCP_LOCK_ROTATE_HEK_CANONICAL_CMD_ID.to_le_bytes()
        );
        assert_checksum(rotate.as_bytes());
    }
}
