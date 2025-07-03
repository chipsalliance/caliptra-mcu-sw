// Licensed under the Apache-2.0 license

extern crate alloc;
use crate::codec::CodecError;
use crate::codec::MessageBuf;
use alloc::boxed::Box;
use async_trait::async_trait;
use libtock_platform::ErrorCode;

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
