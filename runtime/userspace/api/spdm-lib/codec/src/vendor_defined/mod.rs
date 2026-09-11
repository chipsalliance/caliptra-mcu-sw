// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED request / response wire types.

pub mod iana {
    pub mod ocp {
        pub mod caliptra;
    }
}
pub mod pci_sig;

use bitfield_struct::bitfield;
use zerocopy::{
    little_endian::{U16, U32},
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

use crate::{ReqRespCode, ResponseBody, WireError, WireReader, WireWriter};

/// SPDM Standards Body ID registry values used by VENDOR_DEFINED messages.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StandardsBodyId {
    Dmtf = 0x0,
    Tcg = 0x1,
    Usb = 0x2,
    PciSig = 0x3,
    Iana = 0x4,
    HdBaseT = 0x5,
    Mipi = 0x6,
    Cxl = 0x7,
    Jedec = 0x8,
    Vesa = 0x9,
    IanaCbor = 0xA,
    DmtfDsp = 0xB,
}

impl StandardsBodyId {
    #[inline]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0 => Some(Self::Dmtf),
            0x1 => Some(Self::Tcg),
            0x2 => Some(Self::Usb),
            0x3 => Some(Self::PciSig),
            0x4 => Some(Self::Iana),
            0x5 => Some(Self::HdBaseT),
            0x6 => Some(Self::Mipi),
            0x7 => Some(Self::Cxl),
            0x8 => Some(Self::Jedec),
            0x9 => Some(Self::Vesa),
            0xA => Some(Self::IanaCbor),
            0xB => Some(Self::DmtfDsp),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[inline]
    pub const fn vendor_id_len(self) -> Option<u8> {
        match self {
            Self::Dmtf | Self::Vesa => Some(0),
            Self::Tcg
            | Self::Usb
            | Self::PciSig
            | Self::Mipi
            | Self::Cxl
            | Self::Jedec
            | Self::DmtfDsp => Some(2),
            Self::Iana | Self::HdBaseT => Some(4),
            Self::IanaCbor => None,
        }
    }
}

/// `Param1` field of VENDOR_DEFINED_REQUEST / VENDOR_DEFINED_RESPONSE
/// (DSP0274 §10.15 Table 74, §10.16 Table 75).
/// Bits 0..=6 are reserved, and bit 7 is the `LargeReq` / `LargeResp` flag (SPDM 1.4).
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, PartialEq, Eq)]
pub struct VendorDefinedParam1 {
    #[bits(7)]
    pub reserved: u8,
    pub large: bool,
}

impl VendorDefinedParam1 {
    pub const LARGE_REQ: u8 = 0x80;
    pub const LARGE_RESP: u8 = 0x80;
}

/// Fixed part of a VENDOR_DEFINED request body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct VendorDefinedReqPdu {
    pub param1: VendorDefinedParam1,
    pub param2: u8,
    pub standard_id: U16,
    pub vendor_id_len: u8,
}

impl VendorDefinedReqPdu {
    pub const SIZE: usize = 5;
}

const _: () = assert!(core::mem::size_of::<VendorDefinedReqPdu>() == VendorDefinedReqPdu::SIZE);

/// Fixed part of a VENDOR_DEFINED response body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct VendorDefinedRspPdu {
    pub param1: VendorDefinedParam1,
    pub param2: u8,
    pub standard_id: U16,
    pub vendor_id_len: u8,
}

impl VendorDefinedRspPdu {
    pub const SIZE: usize = 5;
}

const _: () = assert!(core::mem::size_of::<VendorDefinedRspPdu>() == VendorDefinedRspPdu::SIZE);

/// Decoded VENDOR_DEFINED request envelope (the fields after the SPDM common header).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VendorDefinedReq<'a> {
    /// Standards body registry value.
    pub standard_id: u16,
    /// Vendor ID bytes (length given by the on-wire `vendor_id_len`).
    pub vendor_id: &'a [u8],
    /// Vendor-defined request payload (length given by the on-wire `req_len` or `large_req_len`).
    pub payload: &'a [u8],
    /// Whether this is a large (SPDM 1.4 LargeReq) request.
    pub is_large: bool,
}

impl VendorDefinedReq<'_> {
    /// Whether this is a large (SPDM 1.4 LargeReq) request.
    #[inline]
    pub fn is_large(&self) -> bool {
        self.is_large
    }

    /// Body size of the corresponding response header (excluding 2-byte SPDM common header).
    /// 7 + vendor_id.len() for standard (9 total), 11 + vendor_id.len() for large (13 total).
    #[inline]
    pub fn rsp_header_body_size(&self) -> usize {
        if self.is_large {
            11 + self.vendor_id.len()
        } else {
            7 + self.vendor_id.len()
        }
    }

    /// Maximum payload length that can be represented in this request mode.
    #[inline]
    pub fn max_length_cap(&self) -> usize {
        if self.is_large {
            u32::MAX as usize
        } else {
            u16::MAX as usize
        }
    }
}

/// Decodes a VENDOR_DEFINED request body (the bytes following the SPDM common header).
///
/// Layout:
/// - Standard: `param1 | param2 | standard_id(U16 LE) | vendor_id_len | vendor_id[..] | req_len(U16 LE) | payload[..]`
/// - Large: `param1(0x80) | param2 | standard_id(U16 LE) | vendor_id_len | vendor_id[..] | reserved(U16) | large_req_len(U32 LE) | payload[..]`
///
/// All fields are bounds-checked; semantic validation of `vendor_id_len` against `standard_id`
/// and reserved bits is left to the caller.
pub fn decode_vendor_defined_req(body: &[u8]) -> Result<VendorDefinedReq<'_>, WireError> {
    let mut r = WireReader::new(body);
    let hdr = r.read::<VendorDefinedReqPdu>()?;
    if hdr.param1.reserved() != 0 || hdr.param2 != 0 {
        return Err(WireError);
    }
    let vendor_id = r.take(hdr.vendor_id_len as usize)?;
    let is_large = hdr.param1.large();

    let req_len = if is_large {
        let rsvd = r.read::<U16>()?;
        if rsvd.get() != 0 {
            return Err(WireError);
        }
        r.read::<U32>()?.get() as usize
    } else {
        r.read::<U16>()?.get() as usize
    };
    let payload = r.take(req_len)?;

    Ok(VendorDefinedReq {
        standard_id: hdr.standard_id.get(),
        vendor_id,
        payload,
        is_large,
    })
}

/// VENDOR_DEFINED_RESPONSE body: echoes the registry identity and carries the payload.
///
/// Encoded (after the SPDM common header written by [`ResponseBody::encode_with_header`])
/// as:
/// - Standard: `param1(0) | param2(0) | standard_id(U16 LE) | vendor_id_len | vendor_id[..] | resp_len(U16 LE) | payload[..]`
/// - Large: `param1(0x80) | param2(0) | standard_id(U16 LE) | vendor_id_len | vendor_id[..] | reserved(U16 0) | large_resp_len(U32 LE) | payload[..]`
pub struct VendorDefinedRspBody<'a> {
    /// Standards body registry value (echoed from the request).
    pub standard_id: u16,
    /// Vendor ID bytes (echoed from the request).
    pub vendor_id: &'a [u8],
    /// Vendor-defined response payload.
    pub payload: &'a [u8],
    /// Whether this is a large (SPDM 1.4 LargeResp) response.
    pub is_large: bool,
}

impl ResponseBody for VendorDefinedRspBody<'_> {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::VENDOR_DEFINED_RESPONSE;

    fn body_size(&self) -> usize {
        let hdr_body_size = if self.is_large { 11 } else { 7 };
        hdr_body_size + self.vendor_id.len() + self.payload.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        let pdu = VendorDefinedRspPdu {
            param1: VendorDefinedParam1::new().with_large(self.is_large),
            param2: 0,
            standard_id: U16::new(self.standard_id),
            vendor_id_len: u8::try_from(self.vendor_id.len()).map_err(|_| WireError)?,
        };
        w.write(&pdu)?;
        w.write_bytes(self.vendor_id)?;
        if self.is_large {
            w.write(&[0u8, 0u8])?; // reserved
            let resp_len = u32::try_from(self.payload.len()).map_err(|_| WireError)?;
            w.write(&U32::new(resp_len))?;
        } else {
            let resp_len = u16::try_from(self.payload.len()).map_err(|_| WireError)?;
            w.write(&U16::new(resp_len))?;
        }
        w.write_bytes(self.payload)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpdmVersion;

    #[test]
    fn test_standard_vdm_decode() {
        // param1=0, param2=0, standard_id=0x0004, vendor_id_len=4, vendor_id=[1,2,3,4], req_len=3, payload=[0xAA, 0xBB, 0xCC]
        let mut body = [0u8; 5 + 4 + 2 + 3];
        body[0] = 0x00; // param1
        body[1] = 0x00; // param2
        body[2..4].copy_from_slice(&4u16.to_le_bytes()); // standard_id = IANA
        body[4] = 4; // vendor_id_len
        body[5..9].copy_from_slice(&[1, 2, 3, 4]); // vendor_id
        body[9..11].copy_from_slice(&3u16.to_le_bytes()); // req_len
        body[11..14].copy_from_slice(&[0xAA, 0xBB, 0xCC]); // payload

        let req = decode_vendor_defined_req(&body).unwrap();
        assert_eq!(
            req,
            VendorDefinedReq {
                standard_id: 0x0004,
                vendor_id: &[1, 2, 3, 4],
                payload: &[0xAA, 0xBB, 0xCC],
                is_large: false,
            }
        );
        assert_eq!(req.rsp_header_body_size(), 7 + 4);
        assert_eq!(req.max_length_cap(), u16::MAX as usize);
    }

    #[test]
    fn test_large_vdm_decode() {
        // param1=0x80, param2=0, standard_id=0x0004, vendor_id_len=4, vendor_id=[1,2,3,4],
        // reserved=0x0000, large_req_len=3, payload=[0xAA, 0xBB, 0xCC]
        let mut body = [0u8; 5 + 4 + 2 + 4 + 3];
        body[0] = 0x80; // param1: large=true
        body[1] = 0x00; // param2
        body[2..4].copy_from_slice(&4u16.to_le_bytes()); // standard_id = IANA
        body[4] = 4; // vendor_id_len
        body[5..9].copy_from_slice(&[1, 2, 3, 4]); // vendor_id
        body[9..11].copy_from_slice(&0u16.to_le_bytes()); // reserved
        body[11..15].copy_from_slice(&3u32.to_le_bytes()); // large_req_len
        body[15..18].copy_from_slice(&[0xAA, 0xBB, 0xCC]); // payload

        let req = decode_vendor_defined_req(&body).unwrap();
        assert_eq!(
            req,
            VendorDefinedReq {
                standard_id: 0x0004,
                vendor_id: &[1, 2, 3, 4],
                payload: &[0xAA, 0xBB, 0xCC],
                is_large: true,
            }
        );
        assert_eq!(req.rsp_header_body_size(), 11 + 4);
        assert_eq!(req.max_length_cap(), u32::MAX as usize);
    }

    #[test]
    fn test_decode_non_zero_reserved_fails() {
        let mut body = [0u8; 5 + 4 + 2 + 4 + 3];
        body[0] = 0x80; // param1: large=true
        body[2..4].copy_from_slice(&4u16.to_le_bytes());
        body[4] = 4;
        body[11..15].copy_from_slice(&3u32.to_le_bytes());

        // 1. Non-zero reserved in param1 (bits 0..=6)
        body[0] = 0x81;
        assert!(decode_vendor_defined_req(&body).is_err());
        body[0] = 0x80;

        // 2. Non-zero param2
        body[1] = 0x01;
        assert!(decode_vendor_defined_req(&body).is_err());
        body[1] = 0x00;

        // 3. Non-zero reserved in large header
        body[9..11].copy_from_slice(&1u16.to_le_bytes());
        assert!(decode_vendor_defined_req(&body).is_err());
    }

    #[test]
    fn test_encode_standard_and_large_rsp_body() {
        let vendor_id = [1, 2, 3, 4];
        let payload = [0x10, 0x20, 0x30];

        // Standard response
        let std_rsp = VendorDefinedRspBody {
            standard_id: 0x0004,
            vendor_id: &vendor_id,
            payload: &payload,
            is_large: false,
        };
        let mut std_buf = [0u8; 16];
        let mut std_w = WireWriter::new(&mut std_buf);
        std_rsp
            .encode_with_header(SpdmVersion::V13, &mut std_w)
            .unwrap();
        assert_eq!(std_rsp.encoded_size(), 16);
        assert_eq!(
            std_buf,
            [
                SpdmVersion::V13.to_u8(),
                ReqRespCode::VENDOR_DEFINED_RESPONSE.0,
                0x00,
                0x00, // param1, param2
                4,
                0, // standard_id = 4
                4, // vendor_id_len
                1,
                2,
                3,
                4, // vendor_id
                3,
                0, // resp_len
                0x10,
                0x20,
                0x30, // payload
            ]
        );

        // Large response
        let large_rsp = VendorDefinedRspBody {
            standard_id: 0x0004,
            vendor_id: &vendor_id,
            payload: &payload,
            is_large: true,
        };
        let mut large_buf = [0u8; 20];
        let mut large_w = WireWriter::new(&mut large_buf);
        large_rsp
            .encode_with_header(SpdmVersion::V14, &mut large_w)
            .unwrap();
        assert_eq!(large_rsp.encoded_size(), 20);
        assert_eq!(
            large_buf,
            [
                SpdmVersion::V14.to_u8(),
                ReqRespCode::VENDOR_DEFINED_RESPONSE.0,
                0x80,
                0x00, // param1 (LargeResp), param2
                4,
                0, // standard_id = 4
                4, // vendor_id_len
                1,
                2,
                3,
                4, // vendor_id
                0,
                0, // reserved
                3,
                0,
                0,
                0, // large_resp_len = 3
                0x10,
                0x20,
                0x30, // payload
            ]
        );
    }

    #[test]
    fn test_decode_truncated_input() {
        let mut body = [0u8; 5 + 4 + 2 + 4 + 3];
        body[0] = 0x80;
        body[4] = 4;
        body[11..15].copy_from_slice(&3u32.to_le_bytes());

        // Truncate at every length up to full size
        for len in 0..body.len() - 1 {
            assert!(decode_vendor_defined_req(&body[..len]).is_err());
        }
    }
}
