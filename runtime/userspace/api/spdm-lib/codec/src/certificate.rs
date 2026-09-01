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

use zerocopy::{
    little_endian::{U16, U32},
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};
use bitfield_struct::bitfield;

/// `Param1` field of GET_CERTIFICATE / CERTIFICATE
/// Bits 0..=3 carry the `SlotID`, and bit 7 is the `LargeCertChain` flag (SPDM 1.4).
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, PartialEq, Eq)]
pub struct GetCertificateParam1 {
    #[bits(4)]
    pub slot_id: u8,
    #[bits(3)]
    _reserved: u8,
    pub large_cert_chain: bool,
}

const PARAM1_SLOT_ID_MASK: u8 = 0xF;

/// 6-byte GET_CERTIFICATE request body (after the 2-byte SPDM
/// common header).
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
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

/// 14-byte GET_CERTIFICATE request body when LargeCertChain=1
/// (after the 2-byte SPDM common header). DSP0274 §10.8 Table 39.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(C)]
pub struct GetCertificateLargeReqBody {
    /// `Param1` — `SlotID` in bits 0..=3, `LargeCertChain` in bit 7.
    pub param1: GetCertificateParam1,
    /// `Param2` — request attributes (bit 0 = SlotSizeRequested).
    pub attributes: u8,
    /// 16-bit offset (0 when LargeCertChain=1).
    pub offset: U16,
    /// 16-bit length (0 when LargeCertChain=1).
    pub length: U16,
    /// 32-bit LargeOffset into the SPDM cert chain (bytes).
    pub large_offset: U32,
    /// 32-bit LargeLength requested (bytes).
    pub large_length: U32,
}

impl GetCertificateLargeReqBody {
    pub const SIZE: usize = 14;
}

const _: () =
    assert!(core::mem::size_of::<GetCertificateLargeReqBody>() == GetCertificateLargeReqBody::SIZE);

/// Parsed representation of a GET_CERTIFICATE request body (standard 6-byte or SPDM 1.4 14-byte large).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GetCertificateReq<'a> {
    Standard(&'a GetCertificateReqBody),
    Large(&'a GetCertificateLargeReqBody),
}

impl<'a> GetCertificateReq<'a> {
    /// Parse a GET_CERTIFICATE request body (excluding the 2-byte common SPDM header).
    pub fn parse(body: &'a [u8]) -> Result<Self, WireError> {
        let param1 = GetCertificateParam1::from_bits(*body.first().ok_or(WireError)?);
        if param1.large_cert_chain() {
            let (req, _) =
                GetCertificateLargeReqBody::ref_from_prefix(body).map_err(|_| WireError)?;
            if req.offset != 0 || req.length != 0 {
                return Err(WireError);
            }
            Ok(Self::Large(req))
        } else {
            if body.len() != GetCertificateReqBody::SIZE {
                return Err(WireError);
            }
            let (req, _) = GetCertificateReqBody::ref_from_prefix(body).map_err(|_| WireError)?;
            Ok(Self::Standard(req))
        }
    }

    /// Whether this is a large (SPDM 1.4 LargeCertChain) request.
    #[inline]
    pub fn is_large(&self) -> bool {
        matches!(self, Self::Large(_))
    }

    /// Target SlotID (bits 0..=3).
    #[inline]
    pub fn slot_id(&self) -> u8 {
        match self {
            Self::Standard(req) => req.slot_id & PARAM1_SLOT_ID_MASK,
            Self::Large(req) => req.param1.slot_id(),
        }
    }

    /// Request attributes (Param2).
    #[inline]
    pub fn attributes(&self) -> u8 {
        match self {
            Self::Standard(req) => req.attributes,
            Self::Large(req) => req.attributes,
        }
    }

    /// Whether the SlotSizeRequested attribute bit is set.
    #[inline]
    pub fn is_slot_size_requested(&self) -> bool {
        (self.attributes() & ATTR_SLOT_SIZE_REQUESTED) != 0
    }

    /// Offset into the cert chain in bytes (16-bit for standard, 32-bit for large).
    #[inline]
    pub fn offset(&self) -> usize {
        match self {
            Self::Standard(req) => req.offset.get() as usize,
            Self::Large(req) => req.large_offset.get() as usize,
        }
    }

    /// Requested portion length in bytes (16-bit for standard, 32-bit for large).
    #[inline]
    pub fn length(&self) -> usize {
        match self {
            Self::Standard(req) => req.length.get() as usize,
            Self::Large(req) => req.large_length.get() as usize,
        }
    }

    /// Body size of the corresponding response header (6 for standard, 14 for large).
    #[inline]
    pub fn rsp_header_body_size(&self) -> usize {
        if self.is_large() {
            CertificateLargeRspBody::SIZE
        } else {
            CertificateRspBody::SIZE
        }
    }

    /// Maximum cert chain length that can be represented in this request mode.
    #[inline]
    pub fn max_length_cap(&self) -> usize {
        if self.is_large() {
            u32::MAX as usize
        } else {
            u16::MAX as usize
        }
    }
}

/// Request attribute bit: requester is asking for the total cert
/// chain size only — responder sets `PortionLength = 0` and
/// `RemainderLength = total_cert_chain_size`.
pub const ATTR_SLOT_SIZE_REQUESTED: u8 = 0x01;

/// 6-byte CERTIFICATE response body header.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
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

/// 14-byte CERTIFICATE response body header when LargeCertChain=1.
#[derive(
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
#[repr(C)]
pub struct CertificateLargeRspBody {
    /// `Param1` — `SlotID` in bits 0..=3, `LargeCertChain` in bit 7.
    pub param1: GetCertificateParam1,
    /// V1.3+: `CertModel` (bits 0..=2), else Reserved.
    pub param2: u8,
    /// 16-bit PortionLength (0 per spec when LargeCertChain=1).
    pub portion_length: U16,
    /// 16-bit RemainderLength (0 per spec when LargeCertChain=1).
    pub remainder_length: U16,
    /// 32-bit LargePortionLength.
    pub large_portion_length: U32,
    /// 32-bit LargeRemainderLength.
    pub large_remainder_length: U32,
}

impl CertificateLargeRspBody {
    pub const SIZE: usize = 14;
}

const _: () =
    assert!(core::mem::size_of::<CertificateLargeRspBody>() == CertificateLargeRspBody::SIZE);

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

/// Builder for a large CERTIFICATE response (SPDM 1.4 LargeCertChain=1).
pub struct CertificateLargeRsp<'a> {
    pub slot_id: u8,
    pub param2: u8,
    pub large_portion_length: u32,
    pub large_remainder_length: u32,
    /// Slice of `large_portion_length` bytes carrying SPDM cert-chain
    /// content for `[large_offset, large_offset + large_portion_length)`.
    pub chain_portion: &'a [u8],
}

impl ResponseBody for CertificateLargeRsp<'_> {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::CERTIFICATE;

    fn body_size(&self) -> usize {
        CertificateLargeRspBody::SIZE + self.chain_portion.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&CertificateLargeRspBody {
            param1: GetCertificateParam1::new()
                .with_slot_id(self.slot_id)
                .with_large_cert_chain(true),
            param2: self.param2,
            portion_length: U16::new(0),
            remainder_length: U16::new(0),
            large_portion_length: U32::new(self.large_portion_length),
            large_remainder_length: U32::new(self.large_remainder_length),
        })?;
        w.write_bytes(self.chain_portion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpdmVersion;

    #[test]
    fn test_large_req_body_size_and_decode() {
        let bytes = [
            0x81, // slot 1 | LargeCertChain (0x80)
            0x01, // SlotSizeRequested
            0x00, 0x00, // offset
            0x00, 0x00, // length
            0x40, 0x00, 0x00, 0x00, // large_offset = 64
            0x00, 0x10, 0x00, 0x00, // large_length = 4096
        ];
        let (req, _) = GetCertificateLargeReqBody::ref_from_prefix(&bytes).unwrap();
        assert_eq!(req.param1.into_bits(), 0x81);
        assert_eq!(req.param1.slot_id(), 1);
        assert!(req.param1.large_cert_chain());
        assert_eq!(req.attributes, ATTR_SLOT_SIZE_REQUESTED);
        assert_eq!(req.large_offset.get(), 64);
        assert_eq!(req.large_length.get(), 4096);
    }

    #[test]
    fn test_large_rsp_builder() {
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let rsp = CertificateLargeRsp {
            slot_id: 1,
            param2: 2,
            large_portion_length: 4,
            large_remainder_length: 100,
            chain_portion: &payload,
        };

        assert_eq!(rsp.body_size(), 14 + 4);
        let mut buf = [0u8; 2 + 14 + 4];
        let mut w = WireWriter::new(&mut buf);
        rsp.encode_with_header(SpdmVersion::V14, &mut w).unwrap();

        assert_eq!(buf[0], SpdmVersion::V14.to_u8());
        assert_eq!(buf[1], ReqRespCode::CERTIFICATE.0);
        assert_eq!(buf[2], 0x81); // slot 1 | LargeCertChain
        assert_eq!(buf[3], 2); // param2
        assert_eq!(&buf[4..6], &[0, 0]); // portion_length == 0
        assert_eq!(&buf[6..8], &[0, 0]); // remainder_length == 0
        assert_eq!(&buf[8..12], &[4, 0, 0, 0]); // large_portion_length == 4
        assert_eq!(&buf[12..16], &[100, 0, 0, 0]); // large_remainder_length == 100
        assert_eq!(&buf[16..20], &payload);
    }

    #[test]
    fn test_get_certificate_req_enum() {
        // Standard request (6 bytes)
        let std_bytes = [
            0x02, // slot 2
            0x01, // SlotSizeRequested
            0x34, 0x12, // offset = 0x1234
            0x00, 0x10, // length = 0x1000
        ];
        let req = GetCertificateReq::parse(&std_bytes).unwrap();
        assert!(!req.is_large());
        assert_eq!(req.slot_id(), 2);
        assert_eq!(req.attributes(), 0x01);
        assert!(req.is_slot_size_requested());
        assert_eq!(req.offset(), 0x1234);
        assert_eq!(req.length(), 0x1000);
        assert_eq!(req.rsp_header_body_size(), CertificateRspBody::SIZE);
        assert_eq!(req.max_length_cap(), u16::MAX as usize);

        // Large request (14 bytes)
        let large_bytes = [
            0x83, // slot 3 | LargeCertChain
            0x00, // attributes
            0x00, 0x00, // offset
            0x00, 0x00, // length
            0x78, 0x56, 0x34, 0x12, // large_offset = 0x12345678
            0x00, 0x00, 0x01, 0x00, // large_length = 0x00010000
        ];
        let req = GetCertificateReq::parse(&large_bytes).unwrap();
        assert!(req.is_large());
        assert_eq!(req.slot_id(), 3);
        assert_eq!(req.attributes(), 0x00);
        assert!(!req.is_slot_size_requested());
        assert_eq!(req.offset(), 0x12345678);
        assert_eq!(req.length(), 0x00010000);
        assert_eq!(req.rsp_header_body_size(), CertificateLargeRspBody::SIZE);
        assert_eq!(req.max_length_cap(), u32::MAX as usize);

        // Truncated request errors
        assert!(GetCertificateReq::parse(&[]).is_err());
        assert!(GetCertificateReq::parse(&[0x00; 5]).is_err());
        assert!(GetCertificateReq::parse(&[0x80; 13]).is_err());
    }
}
