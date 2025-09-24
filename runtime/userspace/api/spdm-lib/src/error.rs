// Licensed under the Apache-2.0 license

use crate::cert_store::CertStoreError;
use crate::chunk_ctx::ChunkError;
use crate::codec::CodecError;
use crate::commands::error_rsp::ErrorCode;
use crate::measurements::common::MeasurementsError;
use crate::protocol::opaque_data::OpaqueDataError;
use crate::protocol::SignCtxError;
use crate::session::SessionError;
use crate::transcript::TranscriptError;
use crate::transport::common::TransportError;
use crate::vdm_handler::VdmError;
use libapi_caliptra::error::CaliptraApiError;

#[derive(Debug)]
pub enum SpdmError {
    UnsupportedVersion,
    InvalidStandardsBodyId,
    InvalidParam,
    BufferTooSmall,
    UnsupportedRequest,
    Codec(CodecError),
    Transport(TransportError),
    Command(CommandError),
    CertStore(CertStoreError),
    CaliptraApi(CaliptraApiError),
    Session(SessionError),
    OpaqueData(OpaqueDataError),
    Vdm(VdmError),
}

pub type SpdmResult<T> = Result<T, SpdmError>;

pub type CommandResult<T> = Result<T, (bool, CommandError)>;

#[derive(Debug, PartialEq)]
pub enum CommandError {
    BufferTooSmall,
    Codec(CodecError),
    ErrorCode(ErrorCode),
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
