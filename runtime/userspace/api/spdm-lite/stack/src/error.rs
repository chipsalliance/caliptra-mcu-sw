// Licensed under the Apache-2.0 license

//! SPDM-level error type for handler ↔ dispatcher boundary.
//!
//! [`SpdmError`] carries the **wire byte** (DSP0274 §10.10.2) and any
//! associated extended-data bytes that an SPDM responder needs to put
//! into an `ERROR` PDU. Handlers return [`SpdmResult<T>`]; the
//! dispatcher catches `Err(SpdmError)` and emits the wire-format
//! response.
//!
//! Below the handler/dispatcher boundary the spdm-lite stack uses
//! the workspace-wide [`McuErrorCode`] / [`McuResult`] type for I/O,
//! allocation, codec, and transport errors. Conversion is implicit
//! via [`From<McuErrorCode> for SpdmError`] — `?` does the lifting at
//! every layer boundary, no `.map_err(...)` ever needed.

use mcu_error::{domain, McuErrorCode};
use mcu_spdm_lite_errors::{as_spdm_wire, is_mctp_error};

/// SPDM-level error suitable for emission as an `ERROR` PDU.
///
/// Currently carries only the DSP0274 §10.10.2 wire byte. Will gain
/// an `ExtData` field when handlers need to emit
/// [`SPDM_RESPONSE_NOT_READY`] / [`SPDM_LARGE_RESPONSE`] /
/// [`SPDM_VENDOR_DEFINED`] with associated bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpdmError {
    spec_byte: u8,
}

/// Convenience alias for `core::result::Result<T, SpdmError>`.
pub type SpdmResult<T> = core::result::Result<T, SpdmError>;

impl SpdmError {
    /// Constructs an [`SpdmError`] from a DSP0274 §10.10.2 spec byte.
    ///
    /// # Parameters
    ///
    /// * `spec_byte` — The DSP0274 `ERROR` PDU `param1` byte (e.g.
    ///   `0x01` for `InvalidRequest`).
    ///
    /// # Returns
    ///
    /// A new `SpdmError` carrying `spec_byte`.
    #[inline]
    pub const fn new(spec_byte: u8) -> Self {
        Self { spec_byte }
    }

    /// Returns the DSP0274 §10.10.2 wire byte for this error.
    ///
    /// # Returns
    ///
    /// The single-byte error code to place in the `ERROR` PDU's
    /// `param1` field.
    #[inline]
    pub const fn spec_byte(&self) -> u8 {
        self.spec_byte
    }
}

/// Implicit conversion from any [`McuErrorCode`] to the closest
/// matching DSP0274 §10.10.2 wire byte.
///
/// This is the single classification point in the stack — handlers
/// just use `?` and the conversion happens automatically.
impl From<McuErrorCode> for SpdmError {
    fn from(e: McuErrorCode) -> Self {
        // Already a wire-encoded SPDM error: extract the byte.
        if let Some(byte) = as_spdm_wire(e) {
            return Self::new(byte);
        }
        // Transport framing failure → caller sent us something malformed.
        if is_mctp_error(e) {
            return Self::new(SPDM_INVALID_REQUEST.spec_byte);
        }
        // Map remaining domains to closest spec bucket.
        match e.domain() {
            // Allocator pool exhausted → ask the requester to retry.
            domain::MEMORY => SPDM_BUSY,
            // Anything else (internal bugs, libtock errors, …) is a
            // catch-all unspecified failure on the responder side.
            _ => SPDM_UNSPECIFIED,
        }
    }
}

/// Implicit conversion from the codec's ZST [`WireError`] — every
/// wire-format read/write failure becomes
/// [`SPDM_INVALID_REQUEST`] when it bubbles up through `?`.
impl From<mcu_spdm_lite_codec::WireError> for SpdmError {
    #[inline]
    fn from(_: mcu_spdm_lite_codec::WireError) -> Self {
        SPDM_INVALID_REQUEST
    }
}

// ---- DSP0274 §10.10.2 wire-byte constants ----------------------------------

/// `InvalidRequest` — malformed or syntactically invalid request.
pub const SPDM_INVALID_REQUEST: SpdmError = SpdmError::new(0x01);
/// `Busy` — responder is unable to accept the request right now
/// (e.g. allocator exhausted). Requester should retry.
pub const SPDM_BUSY: SpdmError = SpdmError::new(0x03);
/// `UnexpectedRequest` — the request is well-formed but illegal in
/// the current connection phase.
pub const SPDM_UNEXPECTED_REQUEST: SpdmError = SpdmError::new(0x04);
/// `Unspecified` — catch-all responder-side failure.
pub const SPDM_UNSPECIFIED: SpdmError = SpdmError::new(0x05);
/// `UnsupportedRequest` — request code is recognised but not
/// implemented by this responder.
pub const SPDM_UNSUPPORTED_REQUEST: SpdmError = SpdmError::new(0x07);
/// `SessionRequired` — request must be issued inside an established
/// secure session.
pub const SPDM_SESSION_REQUIRED: SpdmError = SpdmError::new(0x09);
/// `InvalidSession` — session ID does not refer to a valid session.
pub const SPDM_INVALID_SESSION: SpdmError = SpdmError::new(0x0A);
/// `DecryptError` — secured-message decryption / MAC verification
/// failed.
pub const SPDM_DECRYPT_ERROR: SpdmError = SpdmError::new(0x0F);
/// `VersionMismatch` — requester's SPDM version is not supported.
pub const SPDM_VERSION_MISMATCH: SpdmError = SpdmError::new(0x41);
/// `ResponseNotReady` — responder needs more time; requester should
/// poll with `RESPOND_IF_READY`.
pub const SPDM_RESPONSE_NOT_READY: SpdmError = SpdmError::new(0x42);
/// `RequestResynch` — responder needs the requester to restart the
/// connection from `GET_VERSION`.
pub const SPDM_REQUEST_RESYNCH: SpdmError = SpdmError::new(0x43);
/// `LargeResponse` — response exceeds the single-frame size; requester
/// must use chunked reads.
pub const SPDM_LARGE_RESPONSE: SpdmError = SpdmError::new(0x45);
/// `VendorDefined` — vendor-specific error with extended data.
pub const SPDM_VENDOR_DEFINED: SpdmError = SpdmError::new(0xFE);
