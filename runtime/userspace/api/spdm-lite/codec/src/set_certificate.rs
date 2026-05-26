// Licensed under the Apache-2.0 license

//! SET_CERTIFICATE / SET_CERTIFICATE_RSP wire types (DSP0274 §10.13).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

/// 2-byte SET_CERTIFICATE request body (after the 2-byte SPDM
/// common header).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct SetCertificateReqBody {
    /// `Param1` — SlotID in bits 0..=3, CertModel in bits 4..=6,
    /// Erase in bit 7.
    pub attributes: u8,
    /// `Param2` — KeyPairID for SPDM 1.3 multi-key flows.
    pub key_pair_id: u8,
}

impl SetCertificateReqBody {
    pub const SIZE: usize = 2;

    #[inline]
    pub const fn slot_id(self) -> u8 {
        self.attributes & 0x0f
    }

    #[inline]
    pub const fn cert_model(self) -> u8 {
        (self.attributes >> 4) & 0x07
    }

    #[inline]
    pub const fn erase(self) -> bool {
        (self.attributes & 0x80) != 0
    }
}

const _: () = assert!(core::mem::size_of::<SetCertificateReqBody>() == SetCertificateReqBody::SIZE);

/// 2-byte SET_CERTIFICATE_RSP response body.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct SetCertificateRspBody {
    pub slot_id: u8,
    pub param2: u8,
}

impl SetCertificateRspBody {
    pub const SIZE: usize = 2;
}

const _: () = assert!(core::mem::size_of::<SetCertificateRspBody>() == SetCertificateRspBody::SIZE);

/// Builder for SET_CERTIFICATE_RSP.
pub struct SetCertificateRsp {
    pub slot_id: u8,
}

impl ResponseBody for SetCertificateRsp {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::SET_CERTIFICATE_RSP;

    fn body_size(&self) -> usize {
        SetCertificateRspBody::SIZE
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write(&SetCertificateRspBody {
            slot_id: self.slot_id,
            param2: 0,
        })
    }
}
