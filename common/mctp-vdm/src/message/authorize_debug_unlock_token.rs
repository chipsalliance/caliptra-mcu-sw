// Licensed under the Apache-2.0 license

//! Authorize Debug Unlock Token command (0x0B)
//!
//! Sends the signed token (ECC + MLDSA) to authorize production debug unlock.

use crate::codec::{VdmCodec, VdmCodecError};
use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::request_debug_unlock::{DEBUG_UNLOCK_CHALLENGE_LEN, UNIQUE_DEVICE_ID_LEN};

const ECC_PUBLIC_KEY_DWORDS: usize = 24;
const MLDSA_PUBLIC_KEY_DWORDS: usize = 648;
const ECC_SIGNATURE_DWORDS: usize = 24;
const MLDSA_SIGNATURE_DWORDS: usize = 1157;

/// Authorize Debug Unlock Token Request.
///
/// Layout: length_dwords, unique_device_identifier, unlock_level, reserved,
/// challenge, ecc_public_key, mldsa_public_key, ecc_signature, mldsa_signature.
#[derive(Debug, Clone, PartialEq)]
#[repr(C, packed)]
pub struct AuthorizeDebugUnlockTokenRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Length in DWORDs of the token payload.
    pub length_dwords: u32,
    /// Unique device identifier (must match Request Debug Unlock response).
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_LEN],
    /// Unlock level (1–8).
    pub unlock_level: u8,
    /// Reserved.
    pub reserved: [u8; 3],
    /// Challenge from Request Debug Unlock response.
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_LEN],
    /// ECC P-384 public key (24 u32s, hardware format).
    pub ecc_public_key: [u32; ECC_PUBLIC_KEY_DWORDS],
    /// ML-DSA-87 public key (648 u32s, hardware format).
    pub mldsa_public_key: [u32; MLDSA_PUBLIC_KEY_DWORDS],
    /// ECDSA signature (24 u32s).
    pub ecc_signature: [u32; ECC_SIGNATURE_DWORDS],
    /// MLDSA signature (1157 u32s).
    pub mldsa_signature: [u32; MLDSA_SIGNATURE_DWORDS],
}

impl Default for AuthorizeDebugUnlockTokenRequest {
    fn default() -> Self {
        AuthorizeDebugUnlockTokenRequest {
            hdr: VdmMsgHeader::new_request(VdmCommand::AuthorizeDebugUnlockToken.into()),
            length_dwords: 0,
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_LEN],
            unlock_level: 0,
            reserved: [0u8; 3],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_LEN],
            ecc_public_key: [0u32; ECC_PUBLIC_KEY_DWORDS],
            mldsa_public_key: [0u32; MLDSA_PUBLIC_KEY_DWORDS],
            ecc_signature: [0u32; ECC_SIGNATURE_DWORDS],
            mldsa_signature: [0u32; MLDSA_SIGNATURE_DWORDS],
        }
    }
}

impl VdmCodec for AuthorizeDebugUnlockTokenRequest {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, VdmCodecError> {
        let size = core::mem::size_of::<AuthorizeDebugUnlockTokenRequest>();
        if buffer.len() < size {
            return Err(VdmCodecError::BufferTooShort);
        }
        // Safe: we have a packed repr(C) struct and buffer is large enough.
        let src = self as *const Self as *const [u8; core::mem::size_of::<Self>()];
        buffer[..size].copy_from_slice(unsafe { &*src });
        Ok(size)
    }

    fn decode(buffer: &[u8]) -> Result<Self, VdmCodecError> {
        let size = core::mem::size_of::<AuthorizeDebugUnlockTokenRequest>();
        if buffer.len() < size {
            return Err(VdmCodecError::BufferTooShort);
        }
        let mut out = Self::default();
        let dst = &mut out as *mut Self as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(buffer.as_ptr(), dst, size) };
        Ok(out)
    }
}

/// Authorize Debug Unlock Token Response.
///
/// Payload: completion_code (u32).
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct AuthorizeDebugUnlockTokenResponse {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
}

impl AuthorizeDebugUnlockTokenResponse {
    /// Create a new Authorize Debug Unlock Token response.
    pub fn new(completion_code: u32) -> Self {
        AuthorizeDebugUnlockTokenResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::AuthorizeDebugUnlockToken.into()),
            completion_code,
        }
    }
}

impl Default for AuthorizeDebugUnlockTokenResponse {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{VdmCodec, VdmCodecError};
    use crate::protocol::{VdmCommand, VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_authorize_debug_unlock_token_request_roundtrip() {
        let mut req = AuthorizeDebugUnlockTokenRequest::default();
        req.length_dwords = 100;
        req.unique_device_identifier = [0x11; UNIQUE_DEVICE_ID_LEN];
        req.unlock_level = 5;
        req.challenge = [0x22; DEBUG_UNLOCK_CHALLENGE_LEN];
        for i in 0..ECC_PUBLIC_KEY_DWORDS {
            req.ecc_public_key[i] = i as u32;
        }
        req.mldsa_public_key[0] = 0xDEAD_BEEF;
        req.ecc_signature[0] = 0xCAFE_BABE;
        req.mldsa_signature[0] = 0x1234_5678;

        let size = core::mem::size_of::<AuthorizeDebugUnlockTokenRequest>();
        let mut buffer = vec![0u8; size];
        let written = req.encode(&mut buffer).unwrap();
        assert_eq!(written, size);

        let decoded = AuthorizeDebugUnlockTokenRequest::decode(&buffer).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_authorize_debug_unlock_token_request_encode_buffer_too_short() {
        let req = AuthorizeDebugUnlockTokenRequest::default();
        let mut buffer = [0u8; 4];
        let err = req.encode(&mut buffer).unwrap_err();
        assert_eq!(err, VdmCodecError::BufferTooShort);
    }

    #[test]
    fn test_authorize_debug_unlock_token_request_decode_buffer_too_short() {
        let err = AuthorizeDebugUnlockTokenRequest::decode(&[0u8; 8]).unwrap_err();
        assert_eq!(err, VdmCodecError::BufferTooShort);
    }

    #[test]
    fn test_authorize_debug_unlock_token_response_roundtrip() {
        let resp = AuthorizeDebugUnlockTokenResponse::new(VdmCompletionCode::Success as u32);
        assert!(resp.hdr.is_response());
        assert_eq!(
            resp.hdr.command_code,
            VdmCommand::AuthorizeDebugUnlockToken as u8
        );
        let completion_code = resp.completion_code;
        assert_eq!(completion_code, 0);

        let expected_size = core::mem::size_of::<AuthorizeDebugUnlockTokenResponse>();
        let mut buffer = [0u8; 32];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, expected_size);
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4);

        let decoded = AuthorizeDebugUnlockTokenResponse::decode(&buffer[..size]).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_authorize_debug_unlock_token_response_error_completion() {
        let code = VdmCompletionCode::InvalidData as u32;
        let resp = AuthorizeDebugUnlockTokenResponse::new(code);
        let completion_code = resp.completion_code;
        assert_eq!(completion_code, code);

        let mut buffer = [0u8; 32];
        let size = resp.encode(&mut buffer).unwrap();
        let decoded = AuthorizeDebugUnlockTokenResponse::decode(&buffer[..size]).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_authorize_debug_unlock_token_request_default() {
        let req = AuthorizeDebugUnlockTokenRequest::default();
        assert!(req.hdr.is_request());
        assert_eq!(
            req.hdr.command_code,
            VdmCommand::AuthorizeDebugUnlockToken as u8
        );
        let length_dwords = req.length_dwords;
        let unlock_level = req.unlock_level;
        assert_eq!(length_dwords, 0);
        assert_eq!(unlock_level, 0);
    }

    #[test]
    fn test_authorize_debug_unlock_token_response_default() {
        let resp = AuthorizeDebugUnlockTokenResponse::default();
        assert!(resp.hdr.is_response());
        let completion_code = resp.completion_code;
        assert_eq!(completion_code, 0);
    }

    #[test]
    fn test_authorize_debug_unlock_token_response_decode_buffer_too_short() {
        let err = AuthorizeDebugUnlockTokenResponse::decode(&[0u8; 2]).unwrap_err();
        assert_eq!(err, VdmCodecError::BufferTooShort);
    }

    #[test]
    fn test_authorize_debug_unlock_token_response_encode_buffer_too_short() {
        let resp = AuthorizeDebugUnlockTokenResponse::new(0);
        let mut buf = [0u8; 4];
        let err = resp.encode(&mut buf).unwrap_err();
        assert_eq!(err, VdmCodecError::BufferTooShort);
    }
}
