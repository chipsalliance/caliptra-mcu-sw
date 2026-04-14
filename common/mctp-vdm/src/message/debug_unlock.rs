// Licensed under the Apache-2.0 license

//! Debug Unlock commands (0x0A, 0x0B)
//!
//! - `RequestDebugUnlock` (0x0A): Request a debug unlock challenge.
//! - `AuthorizeDebugUnlockToken` (0x0B): Submit a signed debug unlock token.

use crate::codec::{VdmCodec, VdmCodecError};
use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Size of the unique device identifier in bytes.
pub const UNIQUE_DEVICE_ID_SIZE: usize = 32;

/// Size of the challenge in bytes (ECC P-384 scalar).
pub const DEBUG_UNLOCK_CHALLENGE_SIZE: usize = 48;

/// ECC public key size in u32 words (24 words = 96 bytes for P-384 X || Y).
pub const ECC_PUBLIC_KEY_WORD_SIZE: usize = 24;

/// ML-DSA public key size in u32 words.
pub const MLDSA_PUBLIC_KEY_WORD_SIZE: usize = 648;

/// ECC signature size in u32 words (24 words = 96 bytes for P-384 r || s).
pub const ECC_SIGNATURE_WORD_SIZE: usize = 24;

/// ML-DSA signature size in u32 words.
pub const MLDSA_SIGNATURE_WORD_SIZE: usize = 1157;

// ---------------------------------------------------------------------------
// RequestDebugUnlock (0x0A) — challenge request
// ---------------------------------------------------------------------------

/// Debug Unlock Request.
///
/// Request Payload:
/// - Bytes 0:3 - unlock_level (u8 + 3 reserved)
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DebugUnlockRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Unlock level requested.
    pub unlock_level: u8,
    /// Reserved padding.
    pub reserved: [u8; 3],
}

impl DebugUnlockRequest {
    /// Create a new Debug Unlock Request.
    pub fn new(unlock_level: u8) -> Self {
        DebugUnlockRequest {
            hdr: VdmMsgHeader::new_request(VdmCommand::RequestDebugUnlock.into()),
            unlock_level,
            reserved: [0; 3],
        }
    }
}

impl Default for DebugUnlockRequest {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Debug Unlock Response.
///
/// Response Payload:
/// - Bytes 0:3  - completion_code (u32)
/// - Bytes 4:35 - unique_device_identifier ([u8; 32])
/// - Bytes 36:83 - challenge ([u8; 48])
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DebugUnlockResponse {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
    /// Unique device identifier.
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_SIZE],
    /// Challenge value.
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
}

impl DebugUnlockResponse {
    /// Create a new Debug Unlock Response.
    pub fn new(
        completion_code: u32,
        unique_device_identifier: [u8; UNIQUE_DEVICE_ID_SIZE],
        challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
    ) -> Self {
        DebugUnlockResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::RequestDebugUnlock.into()),
            completion_code,
            unique_device_identifier,
            challenge,
        }
    }
}

impl Default for DebugUnlockResponse {
    fn default() -> Self {
        DebugUnlockResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::RequestDebugUnlock.into()),
            completion_code: 0,
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_SIZE],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
        }
    }
}

// ---------------------------------------------------------------------------
// AuthorizeDebugUnlockToken (0x0B) — token submission
// ---------------------------------------------------------------------------

/// Debug Unlock Token Request header (fixed portion).
///
/// The full wire payload after the header is the variable-length token body.
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DebugUnlockTokenRequestHeader {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Unique device identifier.
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_SIZE],
    /// Unlock level.
    pub unlock_level: u8,
    /// Reserved padding.
    pub reserved: [u8; 3],
    /// Challenge value.
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
}

/// Full Debug Unlock Token Request with all cryptographic fields.
#[derive(Debug, Clone, PartialEq)]
pub struct DebugUnlockTokenRequest {
    /// Fixed header fields.
    pub header: DebugUnlockTokenRequestHeader,
    /// ECC public key.
    pub ecc_public_key: [u32; ECC_PUBLIC_KEY_WORD_SIZE],
    /// ML-DSA public key.
    pub mldsa_public_key: [u32; MLDSA_PUBLIC_KEY_WORD_SIZE],
    /// ECC signature.
    pub ecc_signature: [u32; ECC_SIGNATURE_WORD_SIZE],
    /// ML-DSA signature.
    pub mldsa_signature: [u32; MLDSA_SIGNATURE_WORD_SIZE],
}

impl DebugUnlockTokenRequest {
    /// Create a new Debug Unlock Token Request.
    pub fn new(
        unique_device_identifier: [u8; UNIQUE_DEVICE_ID_SIZE],
        unlock_level: u8,
        challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
        ecc_public_key: [u32; ECC_PUBLIC_KEY_WORD_SIZE],
        mldsa_public_key: [u32; MLDSA_PUBLIC_KEY_WORD_SIZE],
        ecc_signature: [u32; ECC_SIGNATURE_WORD_SIZE],
        mldsa_signature: [u32; MLDSA_SIGNATURE_WORD_SIZE],
    ) -> Self {
        DebugUnlockTokenRequest {
            header: DebugUnlockTokenRequestHeader {
                hdr: VdmMsgHeader::new_request(VdmCommand::AuthorizeDebugUnlockToken.into()),
                unique_device_identifier,
                unlock_level,
                reserved: [0; 3],
                challenge,
            },
            ecc_public_key,
            mldsa_public_key,
            ecc_signature,
            mldsa_signature,
        }
    }

    /// Total wire size of this request.
    fn wire_size() -> usize {
        core::mem::size_of::<DebugUnlockTokenRequestHeader>()
            + ECC_PUBLIC_KEY_WORD_SIZE * 4
            + MLDSA_PUBLIC_KEY_WORD_SIZE * 4
            + ECC_SIGNATURE_WORD_SIZE * 4
            + MLDSA_SIGNATURE_WORD_SIZE * 4
    }
}

impl VdmCodec for DebugUnlockTokenRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, VdmCodecError> {
        let total = Self::wire_size();
        if buffer.len() < total {
            return Err(VdmCodecError::BufferTooShort);
        }

        let hdr_size = core::mem::size_of::<DebugUnlockTokenRequestHeader>();
        self.header.encode(buffer)?;

        let mut offset = hdr_size;
        for arr in [
            self.ecc_public_key.as_slice(),
            self.mldsa_public_key.as_slice(),
            self.ecc_signature.as_slice(),
            self.mldsa_signature.as_slice(),
        ] {
            let bytes = arr.as_bytes();
            buffer[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len();
        }

        Ok(total)
    }

    fn decode(buffer: &[u8]) -> Result<Self, VdmCodecError> {
        let total = Self::wire_size();
        if buffer.len() < total {
            return Err(VdmCodecError::BufferTooShort);
        }

        let hdr_size = core::mem::size_of::<DebugUnlockTokenRequestHeader>();
        let header = DebugUnlockTokenRequestHeader::decode(buffer)?;

        let mut offset = hdr_size;

        fn read_u32_array<const N: usize>(
            buf: &[u8],
            offset: &mut usize,
        ) -> Result<[u32; N], VdmCodecError> {
            let byte_len = N * 4;
            let arr = <[u32; N]>::read_from_bytes(&buf[*offset..*offset + byte_len])
                .map_err(|_| VdmCodecError::BufferTooShort)?;
            *offset += byte_len;
            Ok(arr)
        }

        let ecc_public_key = read_u32_array::<ECC_PUBLIC_KEY_WORD_SIZE>(buffer, &mut offset)?;
        let mldsa_public_key =
            read_u32_array::<MLDSA_PUBLIC_KEY_WORD_SIZE>(buffer, &mut offset)?;
        let ecc_signature = read_u32_array::<ECC_SIGNATURE_WORD_SIZE>(buffer, &mut offset)?;
        let mldsa_signature =
            read_u32_array::<MLDSA_SIGNATURE_WORD_SIZE>(buffer, &mut offset)?;

        Ok(DebugUnlockTokenRequest {
            header,
            ecc_public_key,
            mldsa_public_key,
            ecc_signature,
            mldsa_signature,
        })
    }
}

/// Debug Unlock Token Response.
///
/// Response Payload:
/// - Bytes 0:3 - completion_code (u32)
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DebugUnlockTokenResponse {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
}

impl DebugUnlockTokenResponse {
    /// Create a new Debug Unlock Token Response.
    pub fn new(completion_code: u32) -> Self {
        DebugUnlockTokenResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::AuthorizeDebugUnlockToken.into()),
            completion_code,
        }
    }
}

impl Default for DebugUnlockTokenResponse {
    fn default() -> Self {
        DebugUnlockTokenResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::AuthorizeDebugUnlockToken.into()),
            completion_code: 0,
        }
    }
}
