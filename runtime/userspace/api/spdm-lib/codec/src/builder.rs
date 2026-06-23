// Licensed under the Apache-2.0 license

//! `ResponseBody` trait — every SPDM response PDU implements this.
//!
//! The trait captures three command-independent facts:
//!
//! * The [`ReqRespCode`] this body's [`SpdmMsgHdrPdu`] will carry.
//! * How many bytes the body occupies on the wire (`body_size`).
//! * How to write the body at the writer's current position
//!   (`encode_body`) — the SPDM common header is always written
//!   immediately before, by the caller.
//!
//! Handlers don't write the SPDM common header themselves; the
//! dispatcher's `build_response` helper writes it and then calls
//! [`encode_body`](ResponseBody::encode_body). This way every response
//! starts with the same well-formed `(version, code)` pair without
//! the handler having to remember to write it.

use crate::{ReqRespCode, SpdmMsgHdrPdu, SpdmVersion, WireError, WireWriter};

/// SPDM response body — anything that can be written after the SPDM
/// common header.
pub trait ResponseBody {
    /// SPDM response code carried in the common header's `code` byte.
    const RESPONSE_CODE: ReqRespCode;

    /// Number of body bytes (i.e. everything after the 2-byte common
    /// header). For variable-length bodies (e.g. VERSION's
    /// `entry_count × VersionNumberEntry`), the implementor computes
    /// this from `self`.
    fn body_size(&self) -> usize;

    /// Encode the body at the writer's current position.
    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError>;

    /// Total SPDM-payload size on the wire (common header + body).
    #[inline]
    fn encoded_size(&self) -> usize {
        SpdmMsgHdrPdu::SIZE + self.body_size()
    }

    /// Write `(common-header(version, Self::RESPONSE_CODE) | body)`
    /// at the writer's current position.
    fn encode_with_header(
        &self,
        version: SpdmVersion,
        w: &mut WireWriter<'_>,
    ) -> Result<(), WireError> {
        w.write(&SpdmMsgHdrPdu::new(version, Self::RESPONSE_CODE))?;
        self.encode_body(w)
    }
}
