// Licensed under the Apache-2.0 license

//! KEY_EXCHANGE / KEY_EXCHANGE_RSP wire types (DSP0274 §10.11.3).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    ECC_P384_SIGNATURE_SIZE, ReqRespCode, ResponseBody, SHA384_HASH_SIZE,
    WireError, WireWriter,
};

// ---- Constants -------------------------------------------------------------

/// ECDH P-384 exchange data size (x || y, 48 × 2).
pub const ECDH_P384_EXCHANGE_DATA_SIZE: usize = 96;

/// Random data length in KEY_EXCHANGE req/rsp.
pub const KEY_EXCHANGE_RANDOM_DATA_LEN: usize = 32;

// ---- Request ---------------------------------------------------------------

/// KEY_EXCHANGE request fixed body (after SPDM header).
///
/// After this struct the request carries:
/// `OpaqueDataLength(2) + OpaqueData(variable)`.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct KeyExchangeReqBody {
    /// Measurement summary hash type (0=none, 0xFF=all).
    pub meas_summary_hash_type: u8,
    /// Slot number (0..7).
    pub slot_id: u8,
    /// Requester half of session ID (LE u16).
    pub req_session_id: [u8; 2],
    /// Session policy flags.
    pub session_policy: u8,
    pub _reserved: u8,
    /// Requester random (32 bytes).
    pub random_data: [u8; KEY_EXCHANGE_RANDOM_DATA_LEN],
    /// Requester ECDH public key (96 bytes for P-384).
    pub exchange_data: [u8; ECDH_P384_EXCHANGE_DATA_SIZE],
}

const _: () = assert!(core::mem::size_of::<KeyExchangeReqBody>() == 134);

impl KeyExchangeReqBody {
    /// Requester session ID as u16 (little-endian).
    #[inline]
    pub fn req_session_id_u16(&self) -> u16 {
        u16::from_le_bytes(self.req_session_id)
    }
}

// ---- Response builder ------------------------------------------------------

/// KEY_EXCHANGE_RSP response builder.
///
/// Wire layout (DSP0274 §10.11.3):
/// ```text
/// [ heartbeat_period(1) | reserved(1) | rsp_session_id(2) |
///   mut_auth_requested(1) | slot_id_param(1) | random(32) |
///   exchange_data(96) | meas_summary_hash(0|48) |
///   opaque_len(2) | opaque_data(var) |
///   signature(96) | responder_verify_data(0|48) ]
/// ```
pub struct KeyExchangeRsp<'a> {
    pub rsp_session_id: u16,
    pub slot_id: u8,
    pub random_data: &'a [u8; KEY_EXCHANGE_RANDOM_DATA_LEN],
    pub exchange_data: &'a [u8; ECDH_P384_EXCHANGE_DATA_SIZE],
    pub meas_summary_hash: Option<&'a [u8; SHA384_HASH_SIZE]>,
    pub opaque_data: &'a [u8],
    pub signature: &'a [u8; ECC_P384_SIGNATURE_SIZE],
    /// Present when HBITC is NOT negotiated and session has MAC/ENCRYPT.
    pub responder_verify_data: Option<&'a [u8; SHA384_HASH_SIZE]>,
}

impl ResponseBody for KeyExchangeRsp<'_> {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::KEY_EXCHANGE_RSP;

    fn body_size(&self) -> usize {
        1 + 1 + 2 + 1 + 1
            + KEY_EXCHANGE_RANDOM_DATA_LEN
            + ECDH_P384_EXCHANGE_DATA_SIZE
            + self.meas_hash_len()
            + 2
            + self.opaque_data.len()
            + ECC_P384_SIGNATURE_SIZE
            + self.verify_data_len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        // heartbeat_period = 0 (no heartbeat)
        w.write_bytes(&[0u8])?;
        // reserved
        w.write_bytes(&[0u8])?;
        // rsp_session_id (LE)
        w.write_bytes(&self.rsp_session_id.to_le_bytes())?;
        // mut_auth_requested = 0 (no mutual auth)
        w.write_bytes(&[0u8])?;
        // slot_id_param
        w.write_bytes(&[self.slot_id])?;
        // random_data
        w.write_bytes(self.random_data)?;
        // exchange_data
        w.write_bytes(self.exchange_data)?;
        // optional meas_summary_hash
        if let Some(mh) = self.meas_summary_hash {
            w.write_bytes(mh)?;
        }
        // opaque_len (LE u16) + opaque_data
        let opaque_len = self.opaque_data.len() as u16;
        w.write_bytes(&opaque_len.to_le_bytes())?;
        if !self.opaque_data.is_empty() {
            w.write_bytes(self.opaque_data)?;
        }
        // signature
        w.write_bytes(self.signature)?;
        // optional responder_verify_data
        if let Some(vd) = self.responder_verify_data {
            w.write_bytes(vd)?;
        }
        Ok(())
    }
}

impl KeyExchangeRsp<'_> {
    fn meas_hash_len(&self) -> usize {
        if self.meas_summary_hash.is_some() {
            SHA384_HASH_SIZE
        } else {
            0
        }
    }

    fn verify_data_len(&self) -> usize {
        if self.responder_verify_data.is_some() {
            SHA384_HASH_SIZE
        } else {
            0
        }
    }
}
