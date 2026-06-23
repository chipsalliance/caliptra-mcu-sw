// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED request / response wire types.

pub mod iana {
    pub mod ocp {
        pub mod caliptra;
    }
}
pub mod pci_sig;

use zerocopy::{little_endian::U16, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

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

/// Fixed part of a VENDOR_DEFINED request body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct VendorDefinedReqPdu {
    pub param1: u8,
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
    pub param1: u8,
    pub param2: u8,
    pub standard_id: U16,
    pub vendor_id_len: u8,
}

impl VendorDefinedRspPdu {
    pub const SIZE: usize = 5;
}

const _: () = assert!(core::mem::size_of::<VendorDefinedRspPdu>() == VendorDefinedRspPdu::SIZE);

/// Decoded VENDOR_DEFINED request envelope (the fields after the SPDM common header).
pub struct VendorDefinedReq<'a> {
    /// Standards body registry value.
    pub standard_id: u16,
    /// Vendor ID bytes (length given by the on-wire `vendor_id_len`).
    pub vendor_id: &'a [u8],
    /// Vendor-defined request payload (length given by the on-wire `req_len`).
    pub payload: &'a [u8],
}

/// Decodes a VENDOR_DEFINED request body (the bytes following the SPDM common header).
///
/// Layout: `param1 | param2 | standard_id(U16 LE) | vendor_id_len | vendor_id[..] |
/// req_len(U16 LE) | payload[..]`. All fields are bounds-checked; semantic validation
/// of `vendor_id_len` against `standard_id` is left to the caller.
pub fn decode_vendor_defined_req(body: &[u8]) -> Result<VendorDefinedReq<'_>, WireError> {
    let mut r = WireReader::new(body);
    let hdr = r.read::<VendorDefinedReqPdu>()?;
    let vendor_id = r.take(hdr.vendor_id_len as usize)?;
    let req_len = r.read::<U16>()?.get() as usize;
    let payload = r.take(req_len)?;
    Ok(VendorDefinedReq {
        standard_id: hdr.standard_id.get(),
        vendor_id,
        payload,
    })
}

/// VENDOR_DEFINED_RESPONSE body: echoes the registry identity and carries the payload.
///
/// Encoded (after the SPDM common header written by [`ResponseBody::encode_with_header`])
/// as: `param1 | param2 | standard_id(U16 LE) | vendor_id_len | vendor_id[..] |
/// resp_len(U16 LE) | payload[..]`.
pub struct VendorDefinedRspBody<'a> {
    /// Standards body registry value (echoed from the request).
    pub standard_id: u16,
    /// Vendor ID bytes (echoed from the request).
    pub vendor_id: &'a [u8],
    /// Vendor-defined response payload.
    pub payload: &'a [u8],
}

impl ResponseBody for VendorDefinedRspBody<'_> {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::VENDOR_DEFINED_RESPONSE;

    fn body_size(&self) -> usize {
        // param1 + param2 + standard_id + vendor_id_len + vendor_id + resp_len + payload
        2 + 2 + 1 + self.vendor_id.len() + 2 + self.payload.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&[0u8, 0u8])?; // param1, param2 (reserved)
        w.write(&U16::new(self.standard_id))?;
        w.write(&[self.vendor_id.len() as u8])?; // vendor_id_len
        w.write_bytes(self.vendor_id)?;
        w.write(&U16::new(self.payload.len() as u16))?; // resp_len
        w.write_bytes(self.payload)?;
        Ok(())
    }
}
