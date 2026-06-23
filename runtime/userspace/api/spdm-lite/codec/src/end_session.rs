// Licensed under the Apache-2.0 license

//! END_SESSION / END_SESSION_ACK wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{ReqRespCode, ResponseBody, WireError, WireWriter};

// ---- Request ---------------------------------------------------------------

/// END_SESSION request fixed body (after SPDM header).
///
/// Bit 0 of `attributes` is the Negotiated State Clearing Indicator.
/// This responder does not advertise `CACHE_CAP`, so the bit is ignored
/// by the stack layer; reserved bits are still represented here so the
/// handler can validate them.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct EndSessionReqBody {
    pub attributes: u8,
    pub reserved: u8,
}

const _: () = assert!(core::mem::size_of::<EndSessionReqBody>() == 2);

impl EndSessionReqBody {
    /// Bit 0: negotiated-state clearing indicator.
    pub const CLEAR_NEGOTIATED_STATE: u8 = 0x01;
    /// Reserved bits in Param1.
    pub const RESERVED_MASK: u8 = !Self::CLEAR_NEGOTIATED_STATE;

    /// Whether the requester asked to clear cached negotiated state.
    #[inline]
    pub fn clear_negotiated_state(&self) -> bool {
        self.attributes & Self::CLEAR_NEGOTIATED_STATE != 0
    }

    /// Whether all reserved bits/fields are zero.
    #[inline]
    pub fn reserved_is_zero(&self) -> bool {
        self.attributes & Self::RESERVED_MASK == 0 && self.reserved == 0
    }
}

// ---- Response builder ------------------------------------------------------

/// END_SESSION_ACK response builder.
///
/// Wire layout: `reserved(1) + reserved(1)`.
pub struct EndSessionAck;

impl ResponseBody for EndSessionAck {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::END_SESSION_ACK;

    fn body_size(&self) -> usize {
        2
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        w.write_bytes(&[0u8, 0u8])
    }
}
