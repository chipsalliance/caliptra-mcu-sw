// Licensed under the Apache-2.0 license

//! SPDM-level error type for handler ↔ dispatcher boundary.
//!
//! [`SpdmError`] carries the SPDM `ERROR` wire byte and any
//! associated extended-data bytes that an SPDM responder needs to put
//! into an `ERROR` PDU. Handlers return [`SpdmResult<T>`]; the
//! dispatcher catches `Err(SpdmError)` and emits the wire-format
//! response.
//!
//! Below the handler/dispatcher boundary this stack uses
//! the workspace-wide [`McuErrorCode`] / [`McuResult`] type for I/O,
//! allocation, codec, and transport errors. Conversion is implicit
//! via [`From<McuErrorCode> for SpdmError`] — `?` does the lifting at
//! every layer boundary, no `.map_err(...)` ever needed.

use caliptra_mcu_spdm_errors::{as_spdm_wire, is_mctp_error, is_pal_error, is_vdm_no_response};
use mcu_error::{domain, McuErrorCode};

/// SPDM-level error suitable for emission as an `ERROR` PDU.
///
/// Carries the SPDM `ERROR` wire byte and the one-byte `Param2`
/// error data field used by errors such as `UnsupportedRequest`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpdmError {
    spec_byte: u8,
    error_data: u8,
}

/// Convenience alias for `core::result::Result<T, SpdmError>`.
pub type SpdmResult<T> = core::result::Result<T, SpdmError>;

impl SpdmError {
    /// Constructs a sentinel error that suppresses any SPDM response.
    #[inline]
    pub const fn no_response() -> Self {
        Self {
            spec_byte: 0,
            error_data: 0,
        }
    }

    /// Returns true when this error should be dropped instead of serialized.
    #[inline]
    pub const fn is_no_response(&self) -> bool {
        self.spec_byte == 0
    }

    /// Constructs an [`SpdmError`] from an SPDM `ERROR` spec byte.
    ///
    /// # Parameters
    ///
    /// * `spec_byte` — The SPDM `ERROR` PDU `param1` byte (e.g.
    ///   `0x01` for `InvalidRequest`).
    ///
    /// # Returns
    ///
    /// A new `SpdmError` carrying `spec_byte`.
    #[inline]
    pub const fn new(spec_byte: u8) -> Self {
        Self {
            spec_byte,
            error_data: 0,
        }
    }

    /// Constructs an [`SpdmError`] with an explicit ERROR Param2 byte.
    #[inline]
    pub const fn with_data(self, error_data: u8) -> Self {
        Self { error_data, ..self }
    }

    /// Returns the SPDM `ERROR` wire byte for this error.
    ///
    /// # Returns
    ///
    /// The single-byte error code to place in the `ERROR` PDU's
    /// `param1` field.
    #[inline]
    pub const fn spec_byte(&self) -> u8 {
        self.spec_byte
    }

    /// Returns the ERROR Param2 byte associated with this error.
    #[inline]
    pub const fn error_data(&self) -> u8 {
        self.error_data
    }
}

/// Implicit conversion from any [`McuErrorCode`] to the closest
/// matching SPDM `ERROR` wire byte.
///
/// This is the single classification point in the stack — handlers
/// just use `?` and the conversion happens automatically.
impl From<McuErrorCode> for SpdmError {
    fn from(e: McuErrorCode) -> Self {
        if is_vdm_no_response(e) {
            return Self::no_response();
        }
        // Already a wire-encoded SPDM error: extract the byte.
        if let Some(byte) = as_spdm_wire(e) {
            return Self::new(byte);
        }
        // Transport framing failure → caller sent us something malformed.
        if is_mctp_error(e) {
            return Self::new(SPDM_INVALID_REQUEST.spec_byte);
        }
        if is_pal_error(e) {
            return match e.code() {
                0x0001 => SPDM_REQUEST_RESYNCH,
                _ => SPDM_UNSPECIFIED,
            };
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
impl From<caliptra_mcu_spdm_codec::WireError> for SpdmError {
    #[inline]
    fn from(_: caliptra_mcu_spdm_codec::WireError) -> Self {
        SPDM_INVALID_REQUEST
    }
}

// ---- SPDM ERROR wire-byte constants -----------------------------------------

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
pub const SPDM_SESSION_REQUIRED: SpdmError = SpdmError::new(0x0B);
/// `SessionLimitExceeded` — responder cannot establish more sessions.
pub const SPDM_SESSION_LIMIT_EXCEEDED: SpdmError = SpdmError::new(0x0A);
/// `ResetRequired` — responder requires a reset before the request can complete.
pub const SPDM_RESET_REQUIRED: SpdmError = SpdmError::new(0x0C);
/// `DecryptError` — secured-message decryption / MAC verification
/// failed.
pub const SPDM_DECRYPT_ERROR: SpdmError = SpdmError::new(0x06);
/// `VersionMismatch` — requester's SPDM version is not supported.
pub const SPDM_VERSION_MISMATCH: SpdmError = SpdmError::new(0x41);
/// `ResponseNotReady` — responder needs more time; requester should
/// poll with `RESPOND_IF_READY`.
pub const SPDM_RESPONSE_NOT_READY: SpdmError = SpdmError::new(0x42);
/// `RequestResynch` — responder needs the requester to restart the
/// connection from `GET_VERSION`.
pub const SPDM_REQUEST_RESYNCH: SpdmError = SpdmError::new(0x43);
/// `OperationFailed` — requested operation failed in the responder.
pub const SPDM_OPERATION_FAILED: SpdmError = SpdmError::new(0x44);
/// `LargeResponse` — response exceeds the single-frame size; requester
/// must use chunked reads.
pub const SPDM_LARGE_RESPONSE: SpdmError = SpdmError::new(0x0F);
/// `VendorDefined` — vendor-specific error with extended data.
pub const SPDM_VENDOR_DEFINED: SpdmError = SpdmError::new(0xFF);
