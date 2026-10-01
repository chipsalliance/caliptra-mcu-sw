// Licensed under the Apache-2.0 license

//! KEY_EXCHANGE / KEY_EXCHANGE_RSP wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireReader, WireWriter, SHA384_HASH_SIZE};

// ---- Constants -------------------------------------------------------------

/// ECDH P-384 exchange data size (x || y, 48 x 2).
pub const ECDH_P384_EXCHANGE_DATA_SIZE: usize = 96;

/// Largest ExchangeData field this responder can negotiate.
pub const MAX_EXCHANGE_DATA_SIZE: usize = ECDH_P384_EXCHANGE_DATA_SIZE;

/// Random data length in KEY_EXCHANGE req/rsp.
pub const KEY_EXCHANGE_RANDOM_DATA_LEN: usize = 32;

/// Fixed KEY_EXCHANGE_RSP body bytes before `ExchangeData`.
pub const KEY_EXCHANGE_RSP_FIXED_BODY_SIZE: usize = 6 + KEY_EXCHANGE_RANDOM_DATA_LEN;

/// KEY_EXCHANGE_RSP HeartbeatPeriod (Param1 of the response, DSP0274): a count
/// of seconds. Zero means heartbeat is supported but not desired on this
/// session, so no liveness watchdog runs.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct HeartBeatPeriod(pub u8);

impl HeartBeatPeriod {
    /// Heartbeat supported but not desired: no watchdog on this session.
    pub const DISABLED: HeartBeatPeriod = HeartBeatPeriod(0);

    /// Whole seconds carried by this period.
    #[inline]
    pub fn secs(self) -> u8 {
        self.0
    }

    /// True when a non-zero period was negotiated.
    #[inline]
    pub fn is_enabled(self) -> bool {
        self.0 != 0
    }
}

// ---- Request ---------------------------------------------------------------

/// KEY_EXCHANGE request fixed prefix (after SPDM header, before variable fields).
///
/// After this struct the request carries:
/// - `ExchangeData(96 for ECDH P-384)`
/// - `OpaqueDataLength(2) + SupportedVersionList(variable)`
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct KeyExchangeReqBodyFixed {
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
}

const _: () = assert!(core::mem::size_of::<KeyExchangeReqBodyFixed>() == 38);

impl KeyExchangeReqBodyFixed {
    /// Requester session ID as u16 (little-endian).
    #[inline]
    pub fn req_session_id_u16(&self) -> u16 {
        u16::from_le_bytes(self.req_session_id)
    }
}

/// Parsed KEY_EXCHANGE request body.
///
/// Provides a view over the complete request body that follows the SPDM header,
/// including the variable-length exchange data and opaque data fields.
pub struct KeyExchangeReq<'a> {
    /// Fixed prefix fields.
    pub fixed: &'a KeyExchangeReqBodyFixed,
    /// Requester's ECDH P-384 public key.
    pub exchange_data: &'a [u8],
    /// Opaque data (typically secured-message version selection).
    pub opaque_data: &'a [u8],
}

impl<'a> KeyExchangeReq<'a> {
    /// Parse a KEY_EXCHANGE request body.
    pub fn parse(body: &'a [u8], exchange_data_size: usize) -> Result<Self, WireError> {
        let mut r = WireReader::new(body);
        let fixed = r.read::<KeyExchangeReqBodyFixed>()?;
        let exchange_data = r.take(exchange_data_size)?;
        let opaque_len = u16::from_le_bytes([
            *r.take(1)?.first().ok_or(WireError)?,
            *r.take(1)?.first().ok_or(WireError)?,
        ]);
        let opaque_data = r.take(opaque_len as usize)?;
        Ok(Self {
            fixed,
            exchange_data,
            opaque_data,
        })
    }

    /// Total encoded length of the request body (used for transcript hashing).
    #[inline]
    pub fn encoded_len(&self) -> usize {
        core::mem::size_of::<KeyExchangeReqBodyFixed>()
            + self.exchange_data.len()
            + 2
            + self.opaque_data.len()
    }
}

// ---- Response builder ------------------------------------------------------

/// KEY_EXCHANGE_RSP response builder.
///
/// Wire layout:
/// ```text
/// [ heartbeat_period(1) | reserved(1) | rsp_session_id(2) |
///   mut_auth_requested(1) | req_slot_id_param(1) | random(32) |
///   exchange_data(96) | meas_summary_hash(0|48) |
///   opaque_len(2) | opaque_data(var) |
///   signature(96|4627) | responder_verify_data(0|48) ]
/// ```
pub struct KeyExchangeRsp<'a> {
    pub heartbeat_period: HeartBeatPeriod,
    pub rsp_session_id: u16,
    pub random_data: &'a [u8; KEY_EXCHANGE_RANDOM_DATA_LEN],
    /// Length of responder exchange data already populated in the response buffer.
    pub exchange_data_len: usize,
    pub meas_summary_hash: Option<&'a [u8; SHA384_HASH_SIZE]>,
    pub opaque_data: &'a [u8],
    pub signature: &'a [u8],
    /// Present when HBITC is NOT negotiated and session has MAC/ENCRYPT.
    pub responder_verify_data: Option<&'a [u8; SHA384_HASH_SIZE]>,
}

impl ResponseBody for KeyExchangeRsp<'_> {
    fn response_code(&self) -> ReqRespCode {
        ReqRespCode::KEY_EXCHANGE_RSP
    }

    fn body_size(&self) -> usize {
        KEY_EXCHANGE_RSP_FIXED_BODY_SIZE
            + self.exchange_data_len
            + self.meas_hash_len()
            + 2
            + self.opaque_data.len()
            + self.signature.len()
            + self.verify_data_len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write_bytes(&[self.heartbeat_period.0])?;
        w.write_bytes(&[0u8])?;
        w.write_bytes(&self.rsp_session_id.to_le_bytes())?;
        w.write_bytes(&[0u8])?;
        w.write_bytes(&[0u8])?;
        w.write_bytes(self.random_data)?;
        w.reserve(self.exchange_data_len)?;
        if let Some(mh) = self.meas_summary_hash {
            w.write_bytes(mh)?;
        }
        let opaque_len = self.opaque_data.len() as u16;
        w.write_bytes(&opaque_len.to_le_bytes())?;
        if !self.opaque_data.is_empty() {
            w.write_bytes(self.opaque_data)?;
        }
        if !self.signature.is_empty() {
            w.write_bytes(self.signature)?;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpdmMsgHdrPdu, SpdmVersion};

    fn encode(period: u8) -> ([u8; 256], usize) {
        let random = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let body = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod(period),
            rsp_session_id: 0xABCD,
            random_data: &random,
            exchange_data_len: ECDH_P384_EXCHANGE_DATA_SIZE,
            meas_summary_hash: None,
            opaque_data: &[],
            signature: &[],
            responder_verify_data: None,
        };
        let mut buf = [0u8; 256];
        let mut w = WireWriter::new(&mut buf);
        body.encode_with_header(SpdmVersion::V13, &mut w).unwrap();
        let len = w.position();
        (buf, len)
    }

    #[test]
    fn heartbeat_period_is_first_body_byte() {
        let (buf, _) = encode(3);
        assert_eq!(buf[SpdmMsgHdrPdu::SIZE], 3);
        assert_eq!(buf[SpdmMsgHdrPdu::SIZE + 1], 0);
    }

    #[test]
    fn heartbeat_period_zero_encodes_zero() {
        let (buf, _) = encode(0);
        assert_eq!(buf[SpdmMsgHdrPdu::SIZE], 0);
    }

    #[test]
    fn in_place_exchange_data_is_preserved() {
        let random_data = [0u8; KEY_EXCHANGE_RANDOM_DATA_LEN];
        let response = KeyExchangeRsp {
            heartbeat_period: HeartBeatPeriod::DISABLED,
            rsp_session_id: 1,
            random_data: &random_data,
            exchange_data_len: 4,
            meas_summary_hash: None,
            opaque_data: &[],
            signature: &[],
            responder_verify_data: None,
        };
        let mut encoded = [0xa5; 64];

        response
            .encode_with_header(SpdmVersion::V14, &mut WireWriter::new(&mut encoded))
            .unwrap();

        let exchange_data_start = SpdmMsgHdrPdu::SIZE + KEY_EXCHANGE_RSP_FIXED_BODY_SIZE;
        assert_eq!(
            &encoded[exchange_data_start..exchange_data_start + 4],
            &[0xa5; 4]
        );
    }
}
