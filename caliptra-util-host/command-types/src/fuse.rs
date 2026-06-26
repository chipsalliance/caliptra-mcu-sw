// Licensed under the Apache-2.0 license

//! Fuse Commands
//!
//! Command structures for fuse operations including authorized commands
//! that require a challenge-response HMAC flow.
//!
//! ## Authorization Flow
//!
//! Authorized commands (e.g., `FeProg`) require the caller to:
//! 1. Request a challenge nonce via `GetAuthCmdChallenge`
//! 2. Compute HMAC-SHA384 over `cmd_id(BE) || cmd_body || challenge`
//! 3. Send the command with the 48-byte MAC appended

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use caliptra_mcu_mbox_common::messages::HybridSignature;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Size of the authorization challenge nonce in bytes
pub const AUTH_CMD_CHALLENGE_SIZE: usize = 32;

/// Canonical command identifier for the GET_AUTH_CMD_CHALLENGE command used in sub-command dispatch.
///
/// This is the MCU mailbox FOURCC for `MC_GET_AUTH_CMD_CHALLENGE` (`0x4D41_4343` = "MACC").
/// Used as the `sub_cmd_id` in the SPDM VDM AuthorizedCommand (`0x12`) dispatch.
pub const MC_GET_AUTH_CMD_CHALLENGE_CANONICAL_CMD_ID: u32 = 0x4D41_4343;

/// Canonical command identifier for the FE_PROG command used in HMAC computation.
///
/// This is the MCU mailbox FOURCC for `MC_FE_PROG` (`0x4D43_4650` = "MCFP" in ASCII).
/// It must be used as the `cmd_id` parameter in HMAC-SHA384 authorization across all
/// transports (SPDM VDM and MCU mailbox) to ensure interoperability.
pub const MC_FE_PROG_CANONICAL_CMD_ID: u32 = 0x4D43_4650;

// ---- Get Authorization Command Challenge ----

/// Request a challenge nonce for authorizing privileged commands.
///
/// The returned challenge must be included in the HMAC computation
/// for the subsequent authorized command.
#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromBytes, Immutable)]
pub struct GetAuthCmdChallengeRequest {
    pub flags: u32,
    pub reserved: u32,
}

/// Response containing the challenge nonce.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetAuthCmdChallengeResponse {
    pub common: CommonResponse,
    pub reserved: u32,
    pub challenge: [u8; AUTH_CMD_CHALLENGE_SIZE],
}

impl Default for GetAuthCmdChallengeResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
            reserved: 0,
            challenge: [0u8; AUTH_CMD_CHALLENGE_SIZE],
        }
    }
}

impl CommandRequest for GetAuthCmdChallengeRequest {
    type Response = GetAuthCmdChallengeResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetAuthCmdChallenge;
}

impl CommandResponse for GetAuthCmdChallengeResponse {}

// ---- Field Entropy Programming (Authorized Command) ----

/// Request to program field entropy for a given OTP partition.
///
/// This is an authorized command — the caller must first obtain a challenge
/// via `GetAuthCmdChallenge`, compute ECC and ML-DSA signatures over
/// `cmd_id(BE) || partition(LE) || challenge`, and place the resulting
/// signatures in the `sig` field.
#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct FeProgRequest {
    pub partition: u32,
    pub sig: HybridSignature,
}

/// Response for field entropy programming (header-only on success).
#[repr(C)]
#[derive(Debug, Default, Clone, IntoBytes, FromBytes, Immutable)]
pub struct FeProgResponse {
    pub common: CommonResponse,
}

impl CommandRequest for FeProgRequest {
    type Response = FeProgResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::FeProg;
}

impl CommandResponse for FeProgResponse {}

// ---- Placeholder fuse commands ----

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct FuseReadRequest {
    // Implementation TBD
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct FuseReadResponse {
    pub common: CommonResponse,
    // Implementation TBD
}

impl CommandRequest for FuseReadRequest {
    type Response = FuseReadResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::FuseRead;
}

impl CommandResponse for FuseReadResponse {}
