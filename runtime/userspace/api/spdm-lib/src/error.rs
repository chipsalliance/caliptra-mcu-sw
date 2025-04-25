// Licensed under the Apache-2.0 license

use crate::cert_mgr::DeviceCertsMgrError;
use crate::codec::CodecError;
use crate::commands::error_rsp::ErrorCode;
use crate::transport::TransportError;

#[derive(Debug)]
pub enum SpdmError {
    UnsupportedVersion,
    InvalidParam,
    Codec(CodecError),
    Transport(TransportError),
    Command(CommandError),
    BufferTooSmall,
    UnsupportedRequest,
    CertMgr(DeviceCertsMgrError),
}

pub type SpdmResult<T> = Result<T, SpdmError>;

pub type CommandResult<T> = Result<T, (bool, CommandError)>;

#[derive(Debug, PartialEq)]
pub enum CommandError {
    BufferTooSmall,
    Codec(CodecError),
    ErrorCode(ErrorCode),
    UnsupportedRequest,
}
