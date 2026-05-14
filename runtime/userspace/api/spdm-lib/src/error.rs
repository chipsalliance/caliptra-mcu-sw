// Licensed under the Apache-2.0 license

use crate::cert_store::CertStoreError;
use crate::chunk_ctx::ChunkError;
use crate::codec::CodecError;
use crate::commands::error_rsp::ErrorCode;
use crate::measurements::MeasurementsError;
use crate::protocol::opaque_data::OpaqueDataError;
use crate::protocol::SignCtxError;
use crate::session::SessionError;
use crate::transcript::TranscriptError;
use crate::transport::common::TransportError;
use crate::vdm_handler::VdmError;
use caliptra_mcu_libapi_caliptra::error::CaliptraApiError;
use caliptra_mcu_libsyscall_caliptra::mailbox::MailboxError;

/// Stable byte IDs for each spdm-lib error type.
///
/// A given inner error type uses the same byte value regardless of which
/// parent wraps it, so a packed `error_code()` u32 decodes without
/// per-parent tables. Parents' leaf variants take `0x01..0xDF`; these IDs
/// occupy `0xE0..0xFF`.
pub(crate) mod error_type_id {
    pub const CODEC: u8 = 0xE1;
    pub const TRANSPORT: u8 = 0xE2;
    pub const COMMAND: u8 = 0xE3;
    pub const CERT_STORE: u8 = 0xE4;
    pub const CALIPTRA_API: u8 = 0xE5;
    pub const SESSION: u8 = 0xE6;
    pub const OPAQUE_DATA: u8 = 0xE7;
    pub const VDM: u8 = 0xE8;
    pub const SIGN_CTX: u8 = 0xE9;
    pub const CHUNK: u8 = 0xEA;
    pub const TRANSCRIPT: u8 = 0xEB;
    pub const MEASUREMENT: u8 = 0xEC;
    pub const KEY_SCHEDULE: u8 = 0xED;
    pub const IDE_DRIVER: u8 = 0xEE;
    pub const TDISP_DRIVER: u8 = 0xEF;
    pub const PROTOCOL: u8 = 0xF0;
}

/// SPDM-protocol validation errors raised by the responder before/around
/// command dispatch (version negotiation, vendor ID parsing, request-type
/// rejection, parameter validation).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProtocolError {
    UnsupportedVersion = 0x01,
    InvalidStandardsBodyId = 0x02,
    InvalidParam = 0x03,
    UnsupportedRequest = 0x04,
}

/// SPDM error type, used as the SPDM responder/library's top-level error.
///
/// For no_std use, errors are logged as two compact u32s rather than via
/// formatted printing:
///
/// ```text
///   error_code() = (top << 24) | (inner << 16) | (sub << 8) | leaf
/// ```
///
/// Each byte is the variant ID at one level of the SPDM error hierarchy:
///   * `top`   — SpdmError variant
///   * `inner` — inner-enum variant (e.g. CommandError under Command(_))
///   * `sub`   — next-level variant
///   * `leaf`  — deepest variant ID
///
/// **Stable type IDs**: a variant that wraps another error type uses the
/// same byte from [`error_type_id`] regardless of nesting position (e.g.
/// `CALIPTRA_API = 0xE5` everywhere). Leaf variants use `0x01..0xDF`.
/// A 0 in any lower byte means the path bottoms out earlier.
///
/// All external-error detail (CaliptraApi and the sub-level errors it wraps)
/// is reached via the `CaliptraApi(_)` wrapper. Where the SPDM-side path
/// reaches that wrapper the lower bytes are 0 — the external detail is
/// carried by `ext_code()` instead:
///
/// ```text
///   ext_code() = (kind << 24) | (variant << 16) | (sub << 8) | leaf
/// ```
///
/// Layout:
///   * `kind`    — external-error kind tag
///                   0x00  no external error (error is purely SPDM-internal,
///                         all detail is in `error_code()`)
///                   0x01  CaliptraApiError (mailbox / syscall / crypto / etc.)
///                   0x02  EatError (hoisted from CaliptraApiError::Eat)
///   * `variant` — variant ID within `kind` (`CaliptraApiError::error_code()`
///                 for kind=0x01, or the EatError variant for kind=0x02)
///   * `sub`     — sub-variant tag (kind=0x01 only):
///                   0x00  CaliptraApi variant has no sub-classification
///                   0x01  CaliptraApi::Mailbox(MailboxError::ErrorCode(_))
///                   0x02  CaliptraApi::Mailbox(MailboxError::MailboxError(_))
///                   0x03  CaliptraApi::Syscall(_)
///   * `leaf`    — low byte of the numeric tail (kind=0x01 only):
///                   sub=0x01 or 0x03  tock ErrorCode value
///                   sub=0x02          MailboxError u32 value
///                   sub=0x00          0
///
/// Example log lines (decode wrappers via [`error_type_id`], leaves via the
/// owning enum's `error_code()`):
///
/// ```text
///   SPDM err: protocol 0xF0010000                        # ProtocolError::UnsupportedVersion
///   SPDM err: cmd 0xE3020001                             # cmd → ErrorCode 0x01
///   SPDM err: cmd 0xE3ECE500 ext=0x01130000              # cmd → measurement
///                                                        # → CaliptraApi (InvalidArgDigestSize)
///   SPDM err: session 0xE6080000                         # session → DecodeAeadError
/// ```
#[derive(Debug)]
pub enum SpdmError {
    Protocol(ProtocolError),
    Codec(CodecError),
    Transport(TransportError),
    Command(CommandError),
    Session(SessionError),
}

pub type SpdmResult<T> = Result<T, SpdmError>;

pub type CommandResult<T> = Result<T, (bool, CommandError)>;

#[derive(Debug, PartialEq)]
pub enum CommandError {
    BufferTooSmall,
    Codec(CodecError),
    ErrorCode(ErrorCode),
    UnsupportedAsymAlgo,
    UnsupportedRequest,
    UnsupportedLargeResponse,
    SignCtx(SignCtxError),
    InvalidChunkContext,
    MissingVdmHandler,
    Chunk(ChunkError),
    CertStore(CertStoreError),
    CaliptraApi(CaliptraApiError),
    Transcript(TranscriptError),
    Measurement(MeasurementsError),
    Session(SessionError),
    OpaqueData(OpaqueDataError),
    Vdm(VdmError),
}

impl SpdmError {
    pub fn error_code(&self) -> u32 {
        match self {
            SpdmError::Protocol(e) => {
                ((error_type_id::PROTOCOL as u32) << 24) | ((*e as u8) as u32)
            }
            SpdmError::Codec(e) => ((error_type_id::CODEC as u32) << 24) | ((*e as u8) as u32),
            SpdmError::Transport(e) => ((error_type_id::TRANSPORT as u32) << 24) | e.error_code(),
            SpdmError::Command(e) => ((error_type_id::COMMAND as u32) << 24) | e.error_code(),
            SpdmError::Session(e) => ((error_type_id::SESSION as u32) << 24) | e.error_code(),
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            SpdmError::Protocol(_) => "protocol",
            SpdmError::Codec(_) => "codec",
            SpdmError::Transport(_) => "transport",
            SpdmError::Command(_) => "cmd",
            SpdmError::Session(_) => "session",
        }
    }

    /// Encoded external error detail (see type-level docs). Returns 0 if the
    /// SPDM error doesn't transitively wrap a `CaliptraApiError`.
    pub fn ext_code(&self) -> u32 {
        match self.caliptra_api() {
            Some(e) => encode_ext(e),
            None => 0,
        }
    }

    fn caliptra_api(&self) -> Option<&CaliptraApiError> {
        match self {
            SpdmError::Command(e) => e.caliptra_api(),
            SpdmError::Session(e) => e.caliptra_api(),
            _ => None,
        }
    }
}

impl CommandError {
    pub fn error_code(&self) -> u32 {
        match self {
            CommandError::BufferTooSmall => 0x01_00_00,
            CommandError::ErrorCode(e) => 0x02_00_00 | u32::from(u8::from(*e)),
            CommandError::UnsupportedAsymAlgo => 0x03_00_00,
            CommandError::UnsupportedRequest => 0x04_00_00,
            CommandError::UnsupportedLargeResponse => 0x05_00_00,
            CommandError::InvalidChunkContext => 0x06_00_00,
            CommandError::MissingVdmHandler => 0x07_00_00,
            CommandError::Codec(e) => ((error_type_id::CODEC as u32) << 16) | ((*e as u8) as u32),
            CommandError::SignCtx(e) => ((error_type_id::SIGN_CTX as u32) << 16) | e.error_code(),
            CommandError::Chunk(e) => ((error_type_id::CHUNK as u32) << 16) | ((*e as u8) as u32),
            CommandError::CertStore(e) => {
                ((error_type_id::CERT_STORE as u32) << 16) | e.error_code()
            }
            CommandError::CaliptraApi(_) => (error_type_id::CALIPTRA_API as u32) << 16,
            CommandError::Transcript(e) => {
                ((error_type_id::TRANSCRIPT as u32) << 16) | e.error_code()
            }
            CommandError::Measurement(e) => {
                ((error_type_id::MEASUREMENT as u32) << 16) | e.error_code()
            }
            CommandError::Session(e) => ((error_type_id::SESSION as u32) << 16) | e.error_code(),
            CommandError::OpaqueData(e) => {
                ((error_type_id::OPAQUE_DATA as u32) << 16) | e.error_code()
            }
            CommandError::Vdm(e) => ((error_type_id::VDM as u32) << 16) | e.error_code(),
        }
    }

    pub fn caliptra_api(&self) -> Option<&CaliptraApiError> {
        match self {
            CommandError::CaliptraApi(e) => Some(e),
            CommandError::SignCtx(e) => e.caliptra_api(),
            CommandError::CertStore(e) => e.caliptra_api(),
            CommandError::Transcript(e) => e.caliptra_api(),
            CommandError::Measurement(e) => e.caliptra_api(),
            CommandError::Session(e) => e.caliptra_api(),
            _ => None,
        }
    }
}

/// Encodes the external (non-SPDM) portion of an error chain into the u32
/// layout documented on `SpdmError`. EAT is hoisted to its own kind tag so
/// log lines clearly distinguish CBOR encoding failures from Caliptra
/// mailbox failures.
fn encode_ext(e: &CaliptraApiError) -> u32 {
    if let Some(id) = e.eat_id() {
        return 0x02_00_00_00 | ((id as u32) << 16);
    }
    let kind = 0x01_u32 << 24;
    let variant = (e.error_code() as u32) << 16;
    let (sub, leaf) = match e {
        CaliptraApiError::Mailbox(MailboxError::ErrorCode(ec)) => (0x01u32, (*ec as u32) & 0xFF),
        CaliptraApiError::Mailbox(MailboxError::MailboxError(v)) => (0x02u32, v & 0xFF),
        CaliptraApiError::Syscall(ec) => (0x03u32, (*ec as u32) & 0xFF),
        _ => (0u32, 0u32),
    };
    kind | variant | (sub << 8) | leaf
}
