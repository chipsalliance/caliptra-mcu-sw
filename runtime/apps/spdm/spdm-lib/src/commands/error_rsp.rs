// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CodecResult, MessageBuf};
use crate::error::CommandError;

// SPDM error codes
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ErrorCode {
    InvalidRequest = 0x01,
    Busy = 0x03,
    UnexpectedRequest = 0x04,
    Unspecified = 0x05,
    DecryptError = 0x06,
    UnsupportedRequest = 0x07,
    RequestInFlight = 0x08,
    InvalidResponseCode = 0x09,
    SessionLimitExceeded = 0x0A,
    SessionRequired = 0x0B,
    ResetRequired = 0x0C,
    ResponseTooLarge = 0x0D,
    RequestTooLarge = 0x0E,
    LargeResponse = 0x0F,
    MessageLost = 0x10,
    InvalidPolicy = 0x11,
    VersionMismatch = 0x41,
    ResponseNotReady = 0x42,
    RequestResynch = 0x43,
    OperationFailed = 0x44,
    NoPendingRequests = 0x45,
    VendorDefined = 0xFF,
}

impl From<ErrorCode> for u8 {
    fn from(code: ErrorCode) -> Self {
        code as u8
    }
}

pub type ErrorData = u8;

pub struct ErrorResponse<'a> {
    error_code: ErrorCode,
    error_data: ErrorData,
    extended_error_data: Option<&'a [u8]>,
}

impl<'a> ErrorResponse<'a> {
    pub fn new(
        error_code: ErrorCode,
        error_data: ErrorData,
        extended_error_data: Option<&'a [u8]>,
    ) -> Option<Self> {
        if extended_error_data.map_or(0, |data| data.len()) > 32 {
            return None;
        }
        Some(Self {
            error_code,
            error_data,
            extended_error_data,
        })
    }

    pub fn payload_len(&self) -> usize {
        2 + self.extended_error_data.map_or(0, |data| data.len())
    }
}

impl<'a> Codec for ErrorResponse<'a> {
    fn encode(&self, buf: &mut MessageBuf) -> CodecResult<usize> {
        // make space for the data at the end of the buffer
        buf.put_data(self.payload_len())?;

        // get a mutable slice of the data offset and fill it
        let rsp = buf.data_mut(self.payload_len())?;

        rsp[0] = self.error_code.into();
        rsp[1] = self.error_data;
        if let Some(data) = self.extended_error_data {
            rsp[2..data.len()].copy_from_slice(data);
        }

        buf.pull_data(self.payload_len())?;

        Ok(self.payload_len())
    }

    fn decode(_buf: &mut MessageBuf) -> CodecResult<Self> {
        unimplemented!()
    }
}

pub fn fill_error_response(
    rsp_buf: &mut MessageBuf,
    error_code: ErrorCode,
    error_data: u8,
    extended_data: Option<&[u8]>,
    // ) -> CommandResult<()> {
) -> (bool, CommandError) {
    // SPDM Error response payload
    let error_payload = ErrorResponse::new(error_code, error_data, extended_data);
    if let Some(error_payload) = error_payload {
        let len = match error_payload.encode(rsp_buf) {
            Ok(len) => len,
            Err(e) => return (false, CommandError::Codec(e)),
        };
        // .map_err(|e| return (false, CommandError::Codec(e)));

        rsp_buf
            .push_data(len)
            .map_err(|e| return (false, CommandError::Codec(e)));

        return (true, CommandError::ErrorCode(error_code));
    } else {
        return (false, CommandError::ErrorCode(error_code));
    }
}
