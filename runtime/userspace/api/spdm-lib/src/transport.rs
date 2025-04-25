// Licensed under the Apache-2.0 license

extern crate alloc;
use crate::codec::MessageBuf;
use crate::codec::{Codec, CodecError, CommonCodec, DataKind};
use alloc::boxed::Box;
use async_trait::async_trait;
use bitfield::bitfield;
use libsyscall_caliptra::mctp::{Mctp, MessageInfo};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub type TransportResult<T> = Result<T, TransportError>;

#[async_trait]
pub trait SpdmTransport {
    async fn send_request<'a>(
        &mut self,
        dest_eid: u8,
        req: &mut MessageBuf<'a>,
    ) -> TransportResult<()>;
    async fn receive_response<'a>(&mut self, rsp: &mut MessageBuf<'a>) -> TransportResult<()>;
    async fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<()>;
    async fn send_response<'a>(&mut self, resp: &mut MessageBuf<'a>) -> TransportResult<()>;
    fn max_message_size(&self) -> TransportResult<usize>;
    fn header_size(&self) -> usize;
}

#[derive(Debug)]
pub enum TransportError {
    DriverError,
    BufferTooSmall,
    Codec(CodecError),
    UnexpectedMessageType,
    ReceiveError,
    SendError,
    ResponseNotExpected,
    NoRequestInFlight,
}

// MCTP Transport Implementation

bitfield! {
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct MctpMsgHdr(MSB0 [u8]);
impl Debug;
u8;
    pub ic, set_ic: 0,0;
    pub msg_type, set_msg_type: 7, 0;
}

impl Default for MctpMsgHdr<[u8; 1]> {
    fn default() -> Self {
        MctpMsgHdr([0u8; 1])
    }
}
impl MctpMsgHdr<[u8; 1]> {
    pub fn new(ic: u8, msg_type: u8) -> Self {
        let mut hdr = MctpMsgHdr([0u8; 1]);
        hdr.set_ic(ic);
        hdr.set_msg_type(msg_type);
        hdr
    }
}

impl CommonCodec for MctpMsgHdr<[u8; 1]> {
    const DATA_KIND: DataKind = DataKind::Header;
}
pub struct MctpTransport {
    mctp: Mctp,
    cur_resp_ctx: Option<MessageInfo>,
    cur_req_ctx: Option<u8>,
}

impl MctpTransport {
    pub fn new(drv_num: u32) -> Self {
        Self {
            mctp: Mctp::new(drv_num),
            cur_resp_ctx: None,
            cur_req_ctx: None,
        }
    }
}

#[async_trait]
impl SpdmTransport for MctpTransport {
    async fn send_request<'a>(
        &mut self,
        dest_eid: u8,
        req: &mut MessageBuf<'a>,
    ) -> TransportResult<()> {
        let msg_type = self
            .mctp
            .msg_type()
            .map_err(|_| TransportError::UnexpectedMessageType)?;
        let header = MctpMsgHdr::new(0, msg_type);
        header.encode(req).map_err(TransportError::Codec)?;
        let req_len = req.data_len();
        let req_buf = req
            .data(req_len)
            .map_err(|_| TransportError::BufferTooSmall)?;

        let tag = self
            .mctp
            .send_request(dest_eid, req_buf)
            .await
            .map_err(|_| TransportError::SendError)?;

        self.cur_req_ctx = Some(tag);

        Ok(())
    }

    async fn receive_response<'a>(&mut self, rsp: &mut MessageBuf<'a>) -> TransportResult<()> {
        rsp.reset();

        let max_len = rsp.capacity();
        rsp.put_data(max_len)
            .map_err(|_| TransportError::BufferTooSmall)?;

        let rsp_buf = rsp
            .data_mut(max_len)
            .map_err(|_| TransportError::BufferTooSmall)?;
        let (rsp_len, _msg_info) = if let Some(tag) = self.cur_req_ctx {
            self.mctp
                .receive_response(rsp_buf, tag)
                .await
                .map_err(|_| TransportError::ReceiveError)
        } else {
            Err(TransportError::ResponseNotExpected)
        }?;

        if rsp_len == 0 {
            Err(TransportError::BufferTooSmall)?;
        }

        // Set the length of the message
        rsp.trim(rsp_len as usize)
            .map_err(|_| TransportError::BufferTooSmall)?;

        // Process the transport message header
        let header = MctpMsgHdr::decode(rsp).map_err(TransportError::Codec)?;
        if header.msg_type()
            != self
                .mctp
                .msg_type()
                .map_err(|_| TransportError::UnexpectedMessageType)?
        {
            Err(TransportError::UnexpectedMessageType)?;
        }

        self.cur_req_ctx = None;
        Ok(())
    }

    async fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<()> {
        req.reset();

        let max_len = req.capacity();
        req.put_data(max_len)
            .map_err(|_| TransportError::BufferTooSmall)?;

        let data_buf = req
            .data_mut(max_len)
            .map_err(|_| TransportError::BufferTooSmall)?;

        let (req_len, msg_info) = self
            .mctp
            .receive_request(data_buf)
            .await
            .map_err(|_| TransportError::ReceiveError)?;

        if req_len == 0 {
            Err(TransportError::BufferTooSmall)?;
        }

        // Set the length of the message
        req.trim(req_len as usize)
            .map_err(|_| TransportError::BufferTooSmall)?;

        // Process the transport message header
        let header = MctpMsgHdr::decode(req).map_err(TransportError::Codec)?;

        if header.msg_type()
            != self
                .mctp
                .msg_type()
                .map_err(|_| TransportError::UnexpectedMessageType)?
        {
            Err(TransportError::UnexpectedMessageType)?;
        }

        self.cur_resp_ctx = Some(msg_info);

        Ok(())
    }

    async fn send_response<'a>(&mut self, resp: &mut MessageBuf<'a>) -> TransportResult<()> {
        let msg_type = self
            .mctp
            .msg_type()
            .map_err(|_| TransportError::UnexpectedMessageType)?;
        let header = MctpMsgHdr::new(0, msg_type);
        header.encode(resp).map_err(TransportError::Codec)?;

        let msg_len = resp.msg_len();
        let rsp_buf = resp
            .data(msg_len)
            .map_err(|_| TransportError::BufferTooSmall)?;

        if let Some(msg_info) = self.cur_resp_ctx.clone() {
            self.mctp
                .send_response(rsp_buf, msg_info)
                .await
                .map_err(|_| TransportError::SendError)?
        } else {
            Err(TransportError::NoRequestInFlight)?;
        }

        self.cur_resp_ctx = None;

        Ok(())
    }

    fn max_message_size(&self) -> TransportResult<usize> {
        let max_size = self
            .mctp
            .max_message_size()
            .map_err(|_| TransportError::DriverError)?;
        Ok(max_size as usize - self.header_size())
    }

    fn header_size(&self) -> usize {
        1
    }
}
