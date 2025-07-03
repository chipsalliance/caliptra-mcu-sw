// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::error::CommandError;
use crate::protocol::{ReqRespCode, SpdmMsgHdr, SpdmVersion};
use zerocopy::{FromBytes, Immutable, IntoBytes};

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

#[allow(dead_code)]
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct ErrorResponse {
    error_code: u8,
    error_data: ErrorData,
}

impl ErrorResponse {
    pub fn new(error_code: ErrorCode, error_data: ErrorData) -> Self {
        Self {
            error_code: error_code.into(),
            error_data,
        }
    }
}

impl CommonCodec for ErrorResponse {}

pub fn encode_error_response(
    rsp_buf: &mut MessageBuf,
    spdm_version: SpdmVersion,
    error_code: ErrorCode,
    error_data: u8,
    extended_data: Option<&[u8]>,
) -> (bool, CommandError) {
    let spdm_hdr = SpdmMsgHdr::new(spdm_version, ReqRespCode::Error);
    // Encode SPDM header first
    let mut total_len = match spdm_hdr.encode(rsp_buf) {
        Ok(len) => len,
        Err(e) => return (false, CommandError::Codec(e)),
    };

    // SPDM Error response payload
    let fixed_payload = ErrorResponse::new(error_code, error_data);
    total_len += match fixed_payload.encode(rsp_buf) {
        Ok(len) => len,
        Err(e) => return (false, CommandError::Codec(e)),
    };

    // Encode variable length extended data for the Error response
    if let Some(data) = extended_data {
        let variable_len = data.len();
        if variable_len > 32 {
            return (false, CommandError::BufferTooSmall);
        }

        // make space for the data at the end of the buffer
        let _ = rsp_buf
            .put_data(variable_len)
            .map_err(|e| (false, CommandError::Codec(e)));

        // get a mutable slice of the data offset and fill it
        let variable_payload = match rsp_buf.data_mut(variable_len) {
            Ok(payload) => payload,
            Err(e) => return (false, CommandError::Codec(e)),
        };
        variable_payload.copy_from_slice(data);

        // pull data offset by the length of the variable data
        let _ = rsp_buf
            .pull_data(variable_len)
            .map_err(|e| (false, CommandError::Codec(e)));
        total_len += variable_len;
    }

    // Push data offset up by total payload length
    match rsp_buf.push_data(total_len) {
        Ok(_) => (true, CommandError::ErrorCode(error_code)),
        Err(e) => (false, CommandError::Codec(e)),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{codec::MessageBuf, protocol::SpdmVersion};

    #[test]
    fn test_fill_error_response() {
        let mut raw_buf = [0u8; 64];
        let mut buf = MessageBuf::new(&mut raw_buf);
        let error_code = ErrorCode::InvalidRequest;
        let error_data = 0x01;

        assert!(
            encode_error_response(&mut buf, SpdmVersion::V10, error_code, error_data, None)
                == (true, CommandError::ErrorCode(error_code))
        );
        assert_eq!(buf.data_len(), 4);
        assert!(raw_buf[0] == SpdmVersion::V10.into());
        assert!(raw_buf[1] == ReqRespCode::Error.into());
        assert!(raw_buf[2] == error_code.into());
        assert!(raw_buf[3] == error_data);
    }

    #[test]
    fn test_fill_error_response_with_extended_data() {
        let mut raw_buf: [u8; 64] = [0u8; 64];
        let mut buf = MessageBuf::new(&mut raw_buf);
        let error_code = ErrorCode::InvalidRequest;
        let error_data = 0x01;
        let extended_raw_data = [0x02; 32];
        let extended_data = Some(&extended_raw_data[..]);

        assert!(
            encode_error_response(
                &mut buf,
                SpdmVersion::V10,
                error_code,
                error_data,
                extended_data
            ) == (true, CommandError::ErrorCode(error_code))
        );
        assert_eq!(buf.data_len(), 36);
        assert!(raw_buf[0] == SpdmVersion::V10.into());
        assert!(raw_buf[1] == ReqRespCode::Error.into());
        assert!(raw_buf[2] == error_code.into());
        assert!(raw_buf[3] == error_data);
        assert_eq!(&raw_buf[4..36], extended_raw_data);
    }

    #[test]
    fn test_fill_error_response_with_too_large_extended_data() {
        let mut raw_buf = [0u8; 64];
        let mut buf = MessageBuf::new(&mut raw_buf);
        let error_code = ErrorCode::InvalidRequest;
        let error_data = 0x01;
        let extended_raw_data = [0x02; 33];
        let extended_data = Some(&extended_raw_data[..]);

        assert!(
            encode_error_response(
                &mut buf,
                SpdmVersion::V10,
                error_code,
                error_data,
                extended_data
            ) == (false, CommandError::BufferTooSmall)
        );
        assert_eq!(buf.data_len(), 0);
    }
}
