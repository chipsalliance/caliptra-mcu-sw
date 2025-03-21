// Licensed under the Apache-2.0 license

use thiserror_no_std::Error;

use crate::cert_mgr::DeviceCertsMgrError;
use crate::codec::CodecError;
use crate::commands::error_rsp::ErrorCode;
use crate::transport::TransportError;

#[derive(Error, Debug)]
pub enum SpdmError {
    #[error("Unsupported version")]
    UnsupportedVersion,
    #[error("Invalid Parameter")]
    InvalidParam,
    #[error("Encode/Decode error")]
    Codec(#[from] CodecError),
    #[error("Transport error")]
    Transport(#[from] TransportError),
    #[error("Command handler error")]
    Command(#[from] CommandError),
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("Unsupported request")]
    UnsupportedRequest,
    #[error("Device Certificate Manager error")]
    CertMgr(#[from] DeviceCertsMgrError),
}

pub type SpdmResult<T> = Result<T, SpdmError>;

pub type CommandResult<T> = Result<T, (bool, CommandError)>;

#[derive(Debug, Error, PartialEq)]
pub enum CommandError {
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("Codec error")]
    Codec(#[from] CodecError),
    #[error("Request failed with error code {:?}", .0)]
    ErrorCode(ErrorCode),
    #[error("Unsupported request")]
    UnsupportedRequest,
}
