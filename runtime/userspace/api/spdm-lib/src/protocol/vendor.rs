// Licensed under the Apache-2.0 license

use crate::error::{SpdmError, SpdmResult};

// Maximum length can be up to 255. Update MAX_SPDM_VENDOR_ID_LEN as needed.
pub const MAX_SPDM_VENDOR_ID_LEN: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fn vendor_id_len(&self) -> SpdmResult<u8> {
        match self {
            StandardsBodyId::Dmtf | StandardsBodyId::Vesa => Ok(0),
            StandardsBodyId::Tcg
            | StandardsBodyId::Usb
            | StandardsBodyId::PciSig
            | StandardsBodyId::Mipi
            | StandardsBodyId::Cxl
            | StandardsBodyId::Jedec
            | StandardsBodyId::DmtfDsp => Ok(2),
            StandardsBodyId::Iana | StandardsBodyId::HdBaseT => Ok(4),
            StandardsBodyId::IanaCbor => Err(SpdmError::UnsupportedRequest), // This is a variable field
        }
    }
}

impl TryFrom<u16> for StandardsBodyId {
    type Error = SpdmError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(StandardsBodyId::Dmtf),
            0x1 => Ok(StandardsBodyId::Tcg),
            0x2 => Ok(StandardsBodyId::Usb),
            0x3 => Ok(StandardsBodyId::PciSig),
            0x4 => Ok(StandardsBodyId::Iana),
            0x5 => Ok(StandardsBodyId::HdBaseT),
            0x6 => Ok(StandardsBodyId::Mipi),
            0x7 => Ok(StandardsBodyId::Cxl),
            0x8 => Ok(StandardsBodyId::Jedec),
            0x9 => Ok(StandardsBodyId::Vesa),
            0xA => Ok(StandardsBodyId::IanaCbor),
            0xB => Ok(StandardsBodyId::DmtfDsp),
            _ => Err(SpdmError::InvalidStandardsBodyId),
        }
    }
}
