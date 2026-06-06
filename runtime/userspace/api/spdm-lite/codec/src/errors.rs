// Licensed under the Apache-2.0 license

//! SPDM-specific error code constants produced by the spdm-lite
//! codec.
//!
//! Subdomain bytes and the wire-byte encoding live in
//! [`mcu_spdm_lite_errors`]; this module owns the concrete error
//! constants the codec emits.

use mcu_error::{domain, McuErrorCode};
use mcu_spdm_lite_errors::{spdm_wire, SUBDOMAIN_LOCAL};

// ---- SPDM wire errors (DSP0274 §10.10.2) ------------------------------------

pub const SPDM_INVALID_REQUEST: McuErrorCode = spdm_wire(0x01);
pub const SPDM_BUSY: McuErrorCode = spdm_wire(0x03);
pub const SPDM_UNEXPECTED_REQUEST: McuErrorCode = spdm_wire(0x04);
pub const SPDM_UNSPECIFIED: McuErrorCode = spdm_wire(0x05);
pub const SPDM_DECRYPT_ERROR: McuErrorCode = spdm_wire(0x06);
pub const SPDM_UNSUPPORTED_REQUEST: McuErrorCode = spdm_wire(0x07);
pub const SPDM_SESSION_LIMIT_EXCEEDED: McuErrorCode = spdm_wire(0x0A);
pub const SPDM_SESSION_REQUIRED: McuErrorCode = spdm_wire(0x0B);
pub const SPDM_RESET_REQUIRED: McuErrorCode = spdm_wire(0x0C);
pub const SPDM_LARGE_RESPONSE: McuErrorCode = spdm_wire(0x0F);
pub const SPDM_VERSION_MISMATCH: McuErrorCode = spdm_wire(0x41);
pub const SPDM_RESPONSE_NOT_READY: McuErrorCode = spdm_wire(0x42);
pub const SPDM_REQUEST_RESYNCH: McuErrorCode = spdm_wire(0x43);
pub const SPDM_OPERATION_FAILED: McuErrorCode = spdm_wire(0x44);

// ---- spdm-lite local / codec errors (never on wire) -------------------------

/// Receive buffer is shorter than the 4-byte SPDM common header.
pub const SHORT_HEADER: McuErrorCode = McuErrorCode::new(domain::SPDM, SUBDOMAIN_LOCAL, 0x0001);

/// SPDM version byte is not a recognized DSP0274 version (`0x10..=0x13`).
pub const BAD_VERSION: McuErrorCode = McuErrorCode::new(domain::SPDM, SUBDOMAIN_LOCAL, 0x0002);

/// Generic wire-format read/write failure surfaced from
/// [`WireReader`](super::WireReader) / [`WireWriter`](super::WireWriter).
pub const WIRE: McuErrorCode = McuErrorCode::new(domain::SPDM, SUBDOMAIN_LOCAL, 0x0003);

// Allow `?` on `Result<_, WireError>` inside any handler returning
// `McuResult<_>` / `SpdmResult<_>` — `WireError` is a ZST so the
// conversion is just "produce the WIRE constant".
impl From<super::WireError> for McuErrorCode {
    #[inline]
    fn from(_: super::WireError) -> Self {
        WIRE
    }
}
