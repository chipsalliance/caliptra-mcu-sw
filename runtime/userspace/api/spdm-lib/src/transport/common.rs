// Licensed under the Apache-2.0 license

extern crate alloc;
use crate::codec::CodecError;
use crate::codec::MessageBuf;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_libtock_platform::ErrorCode;

pub type TransportResult<T> = Result<T, TransportError>;

#[async_trait]
pub trait SpdmTransport {
    async fn send_request<'a>(
        &mut self,
        dest_eid: u8,
        req: &mut MessageBuf<'a>,
        secure: Option<bool>,
    ) -> TransportResult<()>;
    async fn receive_response<'a>(&mut self, rsp: &mut MessageBuf<'a>) -> TransportResult<bool>;
    async fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<bool>;
    async fn send_response<'a>(
        &mut self,
        resp: &mut MessageBuf<'a>,
        secure: bool,
    ) -> TransportResult<()>;
    fn max_message_size(&self) -> TransportResult<usize>;
    fn header_size(&self) -> usize;
    fn sequence_num_size_bytes(&self) -> usize {
        0 // No secure message sequence number by default
    }
    fn random_data_size_bytes(&self) -> usize {
        0 // No secure message random data by default
    }
}

#[derive(Debug)]
pub enum TransportError {
    DriverError(ErrorCode),
    Codec(CodecError),
    UnexpectedMessageType,
    UnsupportedMessageType,
    ResponseNotExpected,
    NoRequestInFlight,
    InvalidMessage,
    OperationNotSupported,
}

impl TransportError {
    pub fn error_code(&self) -> u32 {
        match self {
            TransportError::DriverError(e) => 0x01_00 | ((*e as u32) & 0xFF),
            TransportError::UnexpectedMessageType => 0x02_00,
            TransportError::UnsupportedMessageType => 0x03_00,
            TransportError::ResponseNotExpected => 0x04_00,
            TransportError::NoRequestInFlight => 0x05_00,
            TransportError::InvalidMessage => 0x06_00,
            TransportError::OperationNotSupported => 0x07_00,
            TransportError::Codec(e) => {
                ((crate::error::error_type_id::CODEC as u32) << 8) | ((*e as u8) as u32)
            }
        }
    }
}
