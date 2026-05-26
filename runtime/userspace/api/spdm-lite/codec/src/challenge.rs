// Licensed under the Apache-2.0 license

//! CHALLENGE / CHALLENGE_AUTH wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    REQUESTER_CONTEXT_LEN, ReqRespCode, ResponseBody, SHA384_HASH_SIZE,
    SPDM_NONCE_LEN, WireError, WireWriter,
};

// ---- Request ---------------------------------------------------------------

/// CHALLENGE request body (after SPDM header).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct ChallengeReqBody {
    pub slot_id: u8,
    pub meas_summary_hash_type: u8,
    pub nonce: [u8; SPDM_NONCE_LEN],
}

const _: () = assert!(core::mem::size_of::<ChallengeReqBody>() == 34);

// ---- Response builder ------------------------------------------------------

/// CHALLENGE_AUTH response builder.
pub struct ChallengeAuthRsp<'a> {
    pub slot_id: u8,
    pub cert_chain_hash: &'a [u8; SHA384_HASH_SIZE],
    pub nonce: &'a [u8; SPDM_NONCE_LEN],
    /// If Some, a 48-byte measurement summary hash is included.
    pub meas_summary_hash: Option<&'a [u8; SHA384_HASH_SIZE]>,
    pub opaque_len: u16,
    pub requester_context: Option<&'a [u8; REQUESTER_CONTEXT_LEN]>,
    pub signature: &'a [u8],
}

impl ResponseBody for ChallengeAuthRsp<'_> {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::CHALLENGE_AUTH;

    fn body_size(&self) -> usize {
        1 + 1
            + SHA384_HASH_SIZE
            + SPDM_NONCE_LEN
            + self.meas_hash_len()
            + 2
            + self.requester_context_len()
            + self.signature.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write_bytes(&[self.slot_id & 0x0F])?;
        w.write_bytes(&[1u8 << self.slot_id])?;
        w.write_bytes(self.cert_chain_hash)?;
        w.write_bytes(self.nonce)?;
        if let Some(mh) = self.meas_summary_hash {
            w.write_bytes(mh)?;
        }
        w.write_bytes(&self.opaque_len.to_le_bytes())?;
        if let Some(ctx) = self.requester_context {
            w.write_bytes(ctx)?;
        }
        w.write_bytes(self.signature)?;
        Ok(())
    }
}

impl ChallengeAuthRsp<'_> {
    fn requester_context_len(&self) -> usize {
        if self.requester_context.is_some() {
            REQUESTER_CONTEXT_LEN
        } else {
            0
        }
    }

    fn meas_hash_len(&self) -> usize {
        if self.meas_summary_hash.is_some() {
            SHA384_HASH_SIZE
        } else {
            0
        }
    }
}
