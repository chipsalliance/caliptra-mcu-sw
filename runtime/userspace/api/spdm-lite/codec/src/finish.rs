// Licensed under the Apache-2.0 license

//! FINISH / FINISH_RSP wire types (DSP0274 §10.11.4).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

// ---- Request ---------------------------------------------------------------

/// FINISH request fixed body (after SPDM header).
///
/// After this struct the request carries:
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

impl FinishReqBody {
    /// Whether the requester signature is present (bit 0).
    #[inline]
    pub fn signature_present(&self) -> bool {
        self.req_signature_present & 0x01 != 0
    }
}

// ---- Response builder ------------------------------------------------------

/// FINISH_RSP response builder.
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
