// Licensed under the Apache-2.0 license

// MCTP Transport Implementation

extern crate alloc;
use crate::codec::MessageBuf;
use crate::codec::{Codec, CommonCodec, DataKind};
use crate::transport::common::{SpdmTransport, TransportError, TransportResult};
use alloc::boxed::Box;
use async_trait::async_trait;
use bitfield::bitfield;
use libsyscall_caliptra::mctp::{Mctp, MessageInfo};
use zerocopy::{FromBytes, Immutable, IntoBytes};

const MCTP_MSG_HEADER_SIZE: usize = 1;

enum SupportedMsgType {
    Spdm = 0x5,
}

impl TryFrom<u8> for SupportedMsgType {
    type Error = TransportError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x5 => Ok(SupportedMsgType::Spdm),
            _ => Err(TransportError::UnexpectedMessageType),
        }
    }
}

bitfield! {
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable)]
pub struct MctpMsgHdr(MSB0 [u8]);
impl Debug;
u8;
    pub ic, set_ic: 0,0;
    pub msg_type, set_msg_type: 7, 0;
}

impl Default for MctpMsgHdr<[u8; MCTP_MSG_HEADER_SIZE]> {
    fn default() -> Self {
        MctpMsgHdr([0u8; MCTP_MSG_HEADER_SIZE])
    }
}
impl MctpMsgHdr<[u8; MCTP_MSG_HEADER_SIZE]> {
    pub fn new(ic: u8, msg_type: u8) -> Self {
        let mut hdr = MctpMsgHdr([0u8; MCTP_MSG_HEADER_SIZE]);
        hdr.set_ic(ic);
        hdr.set_msg_type(msg_type);
        hdr
    }
}

impl CommonCodec for MctpMsgHdr<[u8; MCTP_MSG_HEADER_SIZE]> {
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
        _secure: Option<bool>,
    ) -> TransportResult<()> {
        let msg_type = self
            .mctp
            .msg_type()
            .map_err(|_| TransportError::UnexpectedMessageType)?;

        let header = MctpMsgHdr::new(0, msg_type);
        let _supported_msg_type: SupportedMsgType = msg_type.try_into()?;
        header.encode(req).map_err(TransportError::Codec)?;
        let req_len = req.data_len();
        let req_buf = req.data(req_len).map_err(TransportError::Codec)?;

        let tag = self
            .mctp
            .send_request(dest_eid, req_buf)
            .await
            .map_err(TransportError::DriverError)?;

        self.cur_req_ctx = Some(tag);

        Ok(())
    }

    async fn receive_response<'a>(&mut self, rsp: &mut MessageBuf<'a>) -> TransportResult<bool> {
        rsp.reset();

        let max_len = rsp.capacity();
        rsp.put_data(max_len).map_err(TransportError::Codec)?;

        let rsp_buf = rsp.data_mut(max_len).map_err(TransportError::Codec)?;
        let (rsp_len, _msg_info) = if let Some(tag) = self.cur_req_ctx {
            self.mctp
                .receive_response(rsp_buf, tag, 0)
                .await
                .map_err(TransportError::DriverError)
        } else {
            Err(TransportError::ResponseNotExpected)
        }?;

        if rsp_len < MCTP_MSG_HEADER_SIZE as u32 {
            Err(TransportError::InvalidMessage)?;
        }

        // Set the length of the message
        rsp.trim(rsp_len as usize).map_err(TransportError::Codec)?;

        // Process the transport message header
        let header = MctpMsgHdr::decode(rsp).map_err(TransportError::Codec)?;
        let expected_msg_type = self
            .mctp
            .msg_type()
            .map_err(|_| TransportError::UnexpectedMessageType)?;

        if header.msg_type() != expected_msg_type {
            return Err(TransportError::UnexpectedMessageType);
        }

        // Check if the message type is supported
        let _supported_msg_type: SupportedMsgType = header.msg_type().try_into()?;

        self.cur_req_ctx = None;
        Ok(false)
    }

    async fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<bool> {
        req.reset();

        let max_len = req.capacity();
        req.put_data(max_len).map_err(TransportError::Codec)?;

        let data_buf = req.data_mut(max_len).map_err(TransportError::Codec)?;

        let (req_len, msg_info) = self
            .mctp
            .receive_request(data_buf)
            .await
            .map_err(TransportError::DriverError)?;

        if req_len == 0 {
            Err(TransportError::InvalidMessage)?;
        }

        // Set the length of the message
        req.trim(req_len as usize).map_err(TransportError::Codec)?;

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

        Ok(false)
    }

    async fn send_response<'a>(
        &mut self,
        resp: &mut MessageBuf<'a>,
        _secure: bool,
    ) -> TransportResult<()> {
        let msg_type = self
            .mctp
            .msg_type()
            .map_err(|_| TransportError::UnexpectedMessageType)?;
        let header = MctpMsgHdr::new(0, msg_type);
        header.encode(resp).map_err(TransportError::Codec)?;

        let msg_len = resp.msg_len();
        let rsp_buf = resp.data(msg_len).map_err(TransportError::Codec)?;

        if let Some(msg_info) = self.cur_resp_ctx.clone() {
            self.mctp
                .send_response(rsp_buf, msg_info)
                .await
                .map_err(TransportError::DriverError)?
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
            .map_err(TransportError::DriverError)?;
        Ok(max_size as usize - self.header_size())
    }

    fn header_size(&self) -> usize {
        MCTP_MSG_HEADER_SIZE
    }
}
