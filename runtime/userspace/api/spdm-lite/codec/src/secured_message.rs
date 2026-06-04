// Licensed under the Apache-2.0 license

//! Secured SPDM message framing.
//!
//! Wire layout:
//! ```text
//! [ session_id(4) | length(2) | encrypted_data(N) | tag(16) ]
//! ```
//!
//! Plaintext inside `encrypted_data`:
//! ```text
//! [ app_data_length(2) | app_data(M) ]
//! ```
//!
//! AAD = `session_id(4) || length(2)` (no sequence number on wire).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::WireError;

/// AES-256-GCM authentication tag size.
pub const AES_256_GCM_TAG_SIZE: usize = 16;

/// Secured message header size (session_id + length).
pub const SECURED_MSG_HDR_SIZE: usize = 6;

/// Secured message header (session_id + length), parsed from
/// incoming secured messages.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct SecuredMessageHeader {
    pub session_id: [u8; 4],
    pub length: [u8; 2],
}

const _: () = assert!(core::mem::size_of::<SecuredMessageHeader>() == SECURED_MSG_HDR_SIZE);

impl SecuredMessageHeader {
    /// Session ID as u32 (little-endian).
    #[inline]
    pub fn session_id_u32(&self) -> u32 {
        u32::from_le_bytes(self.session_id)
    }

    /// Length field as u16 (little-endian).
    /// This is `encrypted_data_len + tag_len`.
    #[inline]
    pub fn length_u16(&self) -> u16 {
        u16::from_le_bytes(self.length)
    }
}

/// Encode the AAD (Associated Authenticated Data) for AEAD.
///
/// AAD = session_id(4, LE) || length(2, LE).
/// Returns 6 (= `SECURED_MSG_HDR_SIZE`).
pub fn encode_aad(session_id: u32, length: u16, out: &mut [u8]) -> Result<usize, WireError> {
    if out.len() < SECURED_MSG_HDR_SIZE {
        return Err(WireError);
    }
    out[0..4].copy_from_slice(&session_id.to_le_bytes());
    out[4..6].copy_from_slice(&length.to_le_bytes());
    Ok(SECURED_MSG_HDR_SIZE)
}
