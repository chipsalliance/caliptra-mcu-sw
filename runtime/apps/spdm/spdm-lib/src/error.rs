// Licensed under the Apache-2.0 license

use thiserror_no_std::Error;

use crate::error_rsp::CommandError;
use crate::message_buf::CodecError;
use crate::transport::TransportError;

#[derive(Error, Debug)]
pub enum SpdmError {
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
}

pub type SpdmResult<T> = Result<T, SpdmError>;
