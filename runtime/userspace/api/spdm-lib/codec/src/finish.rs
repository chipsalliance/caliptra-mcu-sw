// Licensed under the Apache-2.0 license

//! FINISH / FINISH_RSP wire types.

use zerocopy::{little_endian::U16, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

// ---- Request ---------------------------------------------------------------

pub trait FinishReq {
    /// Requester slot ID (used only with mutual auth).
    fn slot_id(&self) -> u8;
    /// Whether the requester signature is present (bit 0).
    fn signature_present(&self) -> bool;
    /// Length of the opaque data field (always 0 for version <= 1.3).
    fn opaque_data_len(&self) -> usize;
    fn size_of(&self) -> usize;
}

/// FINISH request fixed body (after SPDM header, version <= 1.3).
///
/// Starting in version 1.4 a new fixed field was added, which is
/// represented in [FinishReqBody14].
///
/// After this struct a <= v1.3 request carries:
/// - If `signature_present()`: requester signature (96 bytes, ECC P-384)
/// - Requester verify_data (48 bytes, SHA-384 HMAC)
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct FinishReqBody {
    /// Bit 0: requester signature present (mutual auth only).
    pub req_signature_present: u8,
    /// Requester slot ID (used only with mutual auth).
    pub req_slot_id: u8,
}

const _: () = assert!(core::mem::size_of::<FinishReqBody>() == 2);

impl FinishReq for FinishReqBody {
    #[inline]
    fn signature_present(&self) -> bool {
        self.req_signature_present & 0x01 != 0
    }

    #[inline]
    fn slot_id(&self) -> u8 {
        self.req_slot_id
    }

    #[inline]
    fn opaque_data_len(&self) -> usize {
        0
    }

    #[inline]
    fn size_of(&self) -> usize {
        size_of::<Self>()
    }
}

/// FINISH request fixed body (after SPDM header, version 1.4).
///
/// Version 1.4 added the new fixed field `OpaqueDataLength`.
///
/// After this struct the request carries:
/// - Requester OpaqueData (`OpaqueDataLength` bytes)
/// - If `signature_present()`: requester signature (96 bytes, ECC P-384)
/// - Requester verify_data (48 bytes, SHA-384 HMAC)
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct FinishReqBody14 {
    /// Bit 0: requester signature present (mutual auth only).
    pub req_signature_present: u8,
    /// Requester slot ID (used only with mutual auth).
    pub req_slot_id: u8,
    /// The size of the `OpaqueData` field.
    ///
    /// Should be in the range from 0 to 1024.
    pub req_opaque_data_length: U16,
}

const _: () = assert!(core::mem::size_of::<FinishReqBody14>() == 4);

impl FinishReq for FinishReqBody14 {
    #[inline]
    fn signature_present(&self) -> bool {
        self.req_signature_present & 0x01 != 0
    }

    #[inline]
    fn slot_id(&self) -> u8 {
        self.req_slot_id
    }

    #[inline]
    fn opaque_data_len(&self) -> usize {
        self.req_opaque_data_length.get() as usize
    }

    #[inline]
    fn size_of(&self) -> usize {
        size_of::<Self>()
    }
}

// ---- Response builder ------------------------------------------------------

/// FINISH_RSP response builder (version <= 1.3).
///
/// Wire layout: `reserved(1) + reserved(1)`.
/// No ResponderVerifyData when HBITC is NOT negotiated (our case).
pub struct FinishRsp;

impl ResponseBody for FinishRsp {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::FINISH_RSP;

    fn body_size(&self) -> usize {
        2
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write_bytes(&[0u8, 0u8])
    }
}

/// FINISH_RSP response builder for version 1.4.
///
/// Wire layout: `reserved(1) + reserved(1) + OpaqueDataLength(2)`.
/// No opaque data supported at this point.
/// No ResponderVerifyData when HBITC is NOT negotiated (our case).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct FinishRsp14 {
    reserved1: u8,
    reserved2: u8,
    opaque_data_length: U16,
}

const _: () = assert!(core::mem::size_of::<FinishRsp14>() == 4);

impl FinishRsp14 {
    pub fn new() -> Self {
        FinishRsp14 {
            reserved1: 0,
            reserved2: 0,
            opaque_data_length: 0.into(),
        }
    }
}

impl ResponseBody for FinishRsp14 {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::FINISH_RSP;

    fn body_size(&self) -> usize {
        4
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write_bytes(self.as_bytes())
    }
}
