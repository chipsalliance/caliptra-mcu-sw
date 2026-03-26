// Licensed under the Apache-2.0 license

//! Request Debug Unlock command (0x0A)
//!
//! Requests a challenge for production debug unlock.

use crate::protocol::{VdmCommand, VdmMsgHeader};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const UNIQUE_DEVICE_ID_LEN: usize = 32;
pub const DEBUG_UNLOCK_CHALLENGE_LEN: usize = 48;

/// Request Debug Unlock Request.
///
/// Payload: length_dwords (u32), unlock_level (u8), reserved (u8[3]).
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct RequestDebugUnlockRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Length in DWORDs (e.g. 2 for header + payload).
    pub length_dwords: u32,
    /// Unlock level (1–8).
    pub unlock_level: u8,
    /// Reserved.
    pub reserved: [u8; 3],
}

impl RequestDebugUnlockRequest {
    /// Create a new Request Debug Unlock request.
    pub fn new(length_dwords: u32, unlock_level: u8) -> Self {
        RequestDebugUnlockRequest {
            hdr: VdmMsgHeader::new_request(VdmCommand::RequestDebugUnlock.into()),
            length_dwords,
            unlock_level,
            reserved: [0u8; 3],
        }
    }
}

impl Default for RequestDebugUnlockRequest {
    fn default() -> Self {
        Self::new(2, 1)
    }
}

/// Request Debug Unlock Response.
///
/// Payload: completion_code (u32), length_dwords (u32), unique_device_identifier (u8[32]), challenge (u8[48]).
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct RequestDebugUnlockResponse {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
    /// Length in DWORDs of the mailbox payload (e.g. 21).
    pub length_dwords: u32,
    /// Unique device identifier (e.g. UID).
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_LEN],
    /// Challenge for the host to sign.
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_LEN],
}

impl RequestDebugUnlockResponse {
    /// Create a new Request Debug Unlock response.
    pub fn new(
        completion_code: u32,
        length_dwords: u32,
        unique_device_identifier: &[u8; UNIQUE_DEVICE_ID_LEN],
        challenge: &[u8; DEBUG_UNLOCK_CHALLENGE_LEN],
    ) -> Self {
        let mut resp = RequestDebugUnlockResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::RequestDebugUnlock.into()),
            completion_code,
            length_dwords,
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_LEN],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_LEN],
        };
        resp.unique_device_identifier
            .copy_from_slice(unique_device_identifier);
        resp.challenge.copy_from_slice(challenge);
        resp
    }
}

impl Default for RequestDebugUnlockResponse {
    fn default() -> Self {
        RequestDebugUnlockResponse {
            hdr: VdmMsgHeader::new_response(VdmCommand::RequestDebugUnlock.into()),
            completion_code: 0,
            length_dwords: 0,
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_LEN],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_LEN],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{VdmCodec, VdmCodecError};
    use crate::protocol::{VdmCommand, VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_request_debug_unlock_request_roundtrip() {
        let req = RequestDebugUnlockRequest::new(2, 3);
        assert!(req.hdr.is_request());
        assert_eq!(req.hdr.command_code, VdmCommand::RequestDebugUnlock as u8);
        let length_dwords = req.length_dwords;
        let unlock_level = req.unlock_level;
        let reserved = req.reserved;
        assert_eq!(length_dwords, 2);
        assert_eq!(unlock_level, 3);
        assert_eq!(reserved, [0u8; 3]);

        let expected_size = core::mem::size_of::<RequestDebugUnlockRequest>();
        let mut buffer = [0u8; 64];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, expected_size);
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4 + 1 + 3);

        let decoded = RequestDebugUnlockRequest::decode(&buffer[..size]).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_request_debug_unlock_response_roundtrip() {
        let mut uid = [0u8; UNIQUE_DEVICE_ID_LEN];
        uid.copy_from_slice(&[0xAB; UNIQUE_DEVICE_ID_LEN]);
        let mut ch = [0u8; DEBUG_UNLOCK_CHALLENGE_LEN];
        for (i, b) in ch.iter_mut().enumerate() {
            *b = i as u8;
        }
        let resp =
            RequestDebugUnlockResponse::new(VdmCompletionCode::Success as u32, 21, &uid, &ch);
        assert!(resp.hdr.is_response());
        let completion_code = resp.completion_code;
        let length_dwords = resp.length_dwords;
        assert_eq!(completion_code, 0);
        assert_eq!(length_dwords, 21);
        assert_eq!(resp.unique_device_identifier, uid);
        assert_eq!(resp.challenge, ch);

        let expected_size = core::mem::size_of::<RequestDebugUnlockResponse>();
        let mut buffer = [0u8; 256];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, expected_size);

        let decoded = RequestDebugUnlockResponse::decode(&buffer[..size]).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_request_debug_unlock_response_default() {
        let resp = RequestDebugUnlockResponse::default();
        assert!(resp.hdr.is_response());
        let completion_code = resp.completion_code;
        assert_eq!(completion_code, 0);
        assert_eq!(resp.unique_device_identifier, [0u8; UNIQUE_DEVICE_ID_LEN]);
        assert_eq!(resp.challenge, [0u8; DEBUG_UNLOCK_CHALLENGE_LEN]);
    }

    #[test]
    fn test_request_debug_unlock_request_default_matches_new() {
        let a = RequestDebugUnlockRequest::default();
        let b = RequestDebugUnlockRequest::new(2, 1);
        assert_eq!(a, b);
        assert_eq!(a.hdr.command_code, VdmCommand::RequestDebugUnlock as u8);
    }

    #[test]
    fn test_request_debug_unlock_request_decode_buffer_too_short() {
        let err = RequestDebugUnlockRequest::decode(&[0u8; 2]).unwrap_err();
        assert_eq!(err, VdmCodecError::BufferTooShort);
    }

    #[test]
    fn test_request_debug_unlock_response_decode_buffer_too_short() {
        let header_only = core::mem::size_of::<RequestDebugUnlockResponse>() - 1;
        let err = RequestDebugUnlockResponse::decode(&vec![0u8; header_only]).unwrap_err();
        assert_eq!(err, VdmCodecError::BufferTooShort);
    }

    #[test]
    fn test_request_debug_unlock_request_encode_buffer_too_short() {
        let req = RequestDebugUnlockRequest::new(1, 2);
        let mut buf = [0u8; 4];
        let err = req.encode(&mut buf).unwrap_err();
        assert_eq!(err, VdmCodecError::BufferTooShort);
    }
}
