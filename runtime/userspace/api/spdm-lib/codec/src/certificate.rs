// Licensed under the Apache-2.0 license

//! GET_CERTIFICATE / CERTIFICATE wire types (DSP0274 §10.8).
//!
//! ## Request (Table 38)
//!
//! ```text
//!  byte 0     byte 1     byte 2..3   byte 4..5
//! ┌──────────┬──────────┬───────────┬──────────┐
//! │ SlotID   │ Attrib   │ Offset    │ Length   │
//! │ (Param1) │ (Param2) │ (LE u16)  │ (LE u16) │
//! └──────────┴──────────┴───────────┴──────────┘
//! ```
//!
//! `Attrib` bit 0 = `SlotSizeRequested` (V1.2+).
//!
//! ## Response (Table 40)
//!
//! ```text
//!  byte 0     byte 1     byte 2..3        byte 4..5         byte 6..end
//! ┌──────────┬──────────┬─────────────────┬─────────────────┬──────────────┐
//! │ SlotID   │ CertInfo │ PortionLength   │ RemainderLength │ CertChain[..]│
//! │ (Param1) │ (Param2) │ (LE u16)        │ (LE u16)        │              │
//! └──────────┴──────────┴─────────────────┴─────────────────┴──────────────┘
//! ```
//!
//! `CertChain` carries `PortionLength` bytes of the SPDM cert-chain
//! wire format (length(2) | reserved(2) | root_hash(48) | DER).

use zerocopy::{little_endian::U16, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

/// 6-byte GET_CERTIFICATE request body (after the 2-byte SPDM
/// common header).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct GetCertificateReqBody {
    /// `Param1` — `SlotID` in bits 0..=3.
    pub slot_id: u8,
    /// `Param2` — request attributes (bit 0 = SlotSizeRequested).
    pub attributes: u8,
    /// Offset into the SPDM cert chain (bytes).
    pub offset: U16,
    /// Requested length (bytes).
    pub length: U16,
}

impl GetCertificateReqBody {
    pub const SIZE: usize = 6;
}

const _: () = assert!(core::mem::size_of::<GetCertificateReqBody>() == GetCertificateReqBody::SIZE);

/// Request attribute bit: requester is asking for the total cert
/// chain size only — responder sets `PortionLength = 0` and
/// `RemainderLength = total_cert_chain_size`.
pub const ATTR_SLOT_SIZE_REQUESTED: u8 = 0x01;

/// 6-byte CERTIFICATE response body header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct CertificateRspBody {
    pub slot_id: u8,
    /// V1.3: `CertModel` (bits 0..=2), else Reserved.
    pub param2: u8,
    pub portion_length: U16,
    pub remainder_length: U16,
}

impl CertificateRspBody {
    pub const SIZE: usize = 6;
}

const _: () = assert!(core::mem::size_of::<CertificateRspBody>() == CertificateRspBody::SIZE);

/// Builder for a CERTIFICATE response. The handler pre-fills the
/// `chain_portion` slice (from a pool-allocated buffer) before
/// calling [`build_response`](caliptra_mcu_spdm_stack::build).
pub struct CertificateRsp<'a> {
    pub slot_id: u8,
    pub param2: u8,
    pub portion_length: u16,
    pub remainder_length: u16,
    /// Slice of `portion_length` bytes carrying SPDM cert-chain
    /// content for `[offset, offset + portion_length)`.
    pub chain_portion: &'a [u8],
}

impl ResponseBody for CertificateRsp<'_> {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::CERTIFICATE;

    fn body_size(&self) -> usize {
        CertificateRspBody::SIZE + self.chain_portion.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&CertificateRspBody {
            slot_id: self.slot_id,
            param2: self.param2,
            portion_length: U16::new(self.portion_length),
            remainder_length: U16::new(self.remainder_length),
        })?;
        w.write_bytes(self.chain_portion)
    }
}
