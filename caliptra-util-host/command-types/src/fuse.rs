// Licensed under the Apache-2.0 license

//! Fuse Commands
//!
//! Command structures for fuse operations including authorized commands
//! that require a dual asymmetric challenge-response.
//!
//! ## Authorization Flow
//!
//! Authorized commands (e.g., `FeProg`) require the caller to:
//! 1. Request a challenge nonce via `GetAuthCmdChallenge`.
//! 2. Build the pre-image `cmd_id(BE) || cmd_body || nonce` and sign it with
//!    both ECC P-384 (over `SHA-384(pre-image)`) and ML-DSA-87 (over
//!    `SHA-512(pre-image)`), mirroring the prod-debug-unlock idiom.
//! 3. Send the command with the hybrid signature and the vendor public keys
//!    appended (the device holds only their SHA-384 anchor).

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use caliptra_mcu_mbox_common::messages::HybridSignature;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Size of the authorization challenge nonce in bytes.
///
/// Re-exported from `caliptra-mcu-mbox-common`, the single source of truth for
/// the nonce width, so the host and device never diverge.
pub use caliptra_mcu_mbox_common::messages::AUTH_CMD_NONCE_LEN as AUTH_CMD_CHALLENGE_SIZE;

/// ECC P-384 public-key coordinate size (bytes). Two coordinates travel on the wire.
pub const AUTH_PUB_ECC_COORD_SIZE: usize = 48;

/// ML-DSA-87 public-key size (bytes).
pub const AUTH_PUB_MLDSA_SIZE: usize = 2592;

/// Canonical command identifier for the GET_AUTH_CMD_CHALLENGE command used in sub-command dispatch.
///
/// This is the MCU mailbox FOURCC for `MC_GET_AUTH_CMD_CHALLENGE` (`0x4D41_4343` = "MACC").
/// Used as the `sub_cmd_id` in the SPDM VDM AuthorizedCommand (`0x12`) dispatch.
pub const MC_GET_AUTH_CMD_CHALLENGE_CANONICAL_CMD_ID: u32 = 0x4D41_4343;

/// Canonical command identifier for the FE_PROG command used in challenge signing.
///
/// This is the MCU mailbox FOURCC for `MC_FE_PROG` (`0x4D43_4650` = "MCFP" in ASCII).
/// It must be used as the `cmd_id` parameter in asymmetric challenge signing across all
/// transports (SPDM VDM and MCU mailbox) to ensure interoperability.
pub const MC_FE_PROG_CANONICAL_CMD_ID: u32 = 0x4D43_4650;

// ---- Get Authorization Command Challenge ----

/// Request a challenge nonce for authorizing privileged commands.
///
/// The returned challenge must be bound into the signed pre-image
/// (`cmd_id(BE) || cmd_body || nonce`) for the subsequent authorized command.
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
/// via `GetAuthCmdChallenge`, build the pre-image `cmd_id(BE) || partition(LE) ||
/// nonce`, sign it with ECC P-384 (over `SHA-384(pre-image)`) and ML-DSA-87
/// (over `SHA-512(pre-image)`), and place the resulting signatures in `sig`.
///
/// The public keys travel on the wire (the device holds only their SHA-384
/// anchor) and the `nonce` echoes the challenge back (prod-debug-unlock idiom):
/// the device compares it to its stored one-time challenge, then rebuilds the
/// pre-image from this wire copy. Canonical wire layout (after the transport
/// header): `partition(4) | nonce(48) | ecc_pub_x(48) | ecc_pub_y(48) | mldsa_pub(2592) | sig`.
/// The signatures come LAST (nonce + public keys precede them), matching the
/// caliptra-sw `ProductionAuthDebugUnlockToken` field order.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct FeProgRequest {
    pub partition: u32,
    /// Freshness nonce echoed back from `GetAuthCmdChallenge`.
    pub nonce: [u8; AUTH_CMD_CHALLENGE_SIZE],
    /// ECC P-384 verifier public key X coordinate (hashed into the anchor).
    pub ecc_pub_x: [u8; AUTH_PUB_ECC_COORD_SIZE],
    /// ECC P-384 verifier public key Y coordinate.
    pub ecc_pub_y: [u8; AUTH_PUB_ECC_COORD_SIZE],
    /// ML-DSA-87 verifier public key.
    pub mldsa_pub: [u8; AUTH_PUB_MLDSA_SIZE],
    /// Hybrid signature (ECDSA P-384 r||s then ML-DSA-87), placed LAST.
    pub sig: HybridSignature,
}

// Hand-written `Default`: arrays with > 32 elements have no derive `Default`.
impl Default for FeProgRequest {
    fn default() -> Self {
        Self {
            partition: 0,
            nonce: [0u8; AUTH_CMD_CHALLENGE_SIZE],
            ecc_pub_x: [0u8; AUTH_PUB_ECC_COORD_SIZE],
            ecc_pub_y: [0u8; AUTH_PUB_ECC_COORD_SIZE],
            mldsa_pub: [0u8; AUTH_PUB_MLDSA_SIZE],
            sig: HybridSignature::default(),
        }
    }
}

// Canonical wire layout: partition(4) | nonce(48) | ecc_pub_x(48) | ecc_pub_y(48) | mldsa_pub(2592) | sig
const _: () = assert!(
    core::mem::size_of::<FeProgRequest>()
        == core::mem::size_of::<u32>()
            + AUTH_CMD_CHALLENGE_SIZE
            + AUTH_PUB_ECC_COORD_SIZE
            + AUTH_PUB_ECC_COORD_SIZE
            + AUTH_PUB_MLDSA_SIZE
            + core::mem::size_of::<HybridSignature>()
);
const _: () = assert!(core::mem::offset_of!(FeProgRequest, nonce) == core::mem::size_of::<u32>());
const _: () = assert!(
    core::mem::offset_of!(FeProgRequest, ecc_pub_x)
        == core::mem::offset_of!(FeProgRequest, nonce) + AUTH_CMD_CHALLENGE_SIZE
);
const _: () = assert!(
    core::mem::offset_of!(FeProgRequest, ecc_pub_y)
        == core::mem::offset_of!(FeProgRequest, ecc_pub_x) + AUTH_PUB_ECC_COORD_SIZE
);
const _: () = assert!(
    core::mem::offset_of!(FeProgRequest, mldsa_pub)
        == core::mem::offset_of!(FeProgRequest, ecc_pub_y) + AUTH_PUB_ECC_COORD_SIZE
);
const _: () = assert!(
    core::mem::offset_of!(FeProgRequest, sig)
        == core::mem::offset_of!(FeProgRequest, mldsa_pub) + AUTH_PUB_MLDSA_SIZE
);

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
