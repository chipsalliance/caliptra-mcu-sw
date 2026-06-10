// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED request / response wire types.

use zerocopy::{little_endian::U16, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

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

    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Fixed part of a VENDOR_DEFINED_REQUEST body after the common header.
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

/// Fixed part of a VENDOR_DEFINED_RESPONSE body after the common header.
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
