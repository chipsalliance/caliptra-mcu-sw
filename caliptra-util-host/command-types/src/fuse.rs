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
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Size of the authorization challenge nonce in bytes
pub const AUTH_CMD_CHALLENGE_SIZE: usize = 32;

/// Size of the HMAC-SHA384 MAC in bytes
pub const AUTH_CMD_MAC_SIZE: usize = 48;

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
/// via `GetAuthCmdChallenge`, compute HMAC-SHA384 over
/// `cmd_id(BE) || partition(LE) || challenge`, and place the resulting
/// 48-byte MAC in the `mac` field.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct FeProgRequest {
    pub partition: u32,
    /// HMAC-SHA384 authorization token (48 bytes).
    /// Computed over `cmd_id(BE, 4) || partition(LE, 4) || challenge(32)`.
    pub mac: [u8; AUTH_CMD_MAC_SIZE],
}

impl Default for FeProgRequest {
    fn default() -> Self {
        Self {
            partition: 0,
            mac: [0u8; AUTH_CMD_MAC_SIZE],
        }
    }
}

/// Response for field entropy programming (header-only on success).
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct FeProgResponse {
    pub common: CommonResponse,
}

impl Default for FeProgResponse {
    fn default() -> Self {
        Self {
            common: CommonResponse { fips_status: 0 },
        }
    }
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
