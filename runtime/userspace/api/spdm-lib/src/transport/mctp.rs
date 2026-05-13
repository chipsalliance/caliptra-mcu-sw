// Licensed under the Apache-2.0 license

// MCTP Transport Implementation

extern crate alloc;
use crate::codec::MessageBuf;
use crate::transport::common::{SpdmTransport, TransportError, TransportResult};
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_libsyscall_caliptra::mctp::{Mctp, MessageInfo};

const MCTP_MSG_HEADER_SIZE: usize = 1;
const MCTP_SPDM_MSG_TYPE: u8 = 0x5;

fn validate_mctp_msg_type(msg_type: u8) -> TransportResult<()> {
    if msg_type == MCTP_SPDM_MSG_TYPE {
        Ok(())
    } else {
        Err(TransportError::UnexpectedMessageType)
    }
}

fn encode_mctp_header(buf: &mut MessageBuf<'_>, msg_type: u8) -> TransportResult<()> {
    buf.push_data(MCTP_MSG_HEADER_SIZE)
        .map_err(TransportError::Codec)?;
    buf.data_mut(MCTP_MSG_HEADER_SIZE)
        .map_err(TransportError::Codec)?[0] = msg_type;
    buf.push_head(MCTP_MSG_HEADER_SIZE)
        .map_err(TransportError::Codec)
}

fn decode_mctp_header(buf: &mut MessageBuf<'_>) -> TransportResult<u8> {
    let msg_type = buf
        .data(MCTP_MSG_HEADER_SIZE)
        .map_err(TransportError::Codec)?[0];
    buf.pull_data(MCTP_MSG_HEADER_SIZE)
        .map_err(TransportError::Codec)?;
    buf.pull_head(MCTP_MSG_HEADER_SIZE)
        .map_err(TransportError::Codec)?;
    Ok(msg_type)
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

        validate_mctp_msg_type(msg_type)?;
        encode_mctp_header(req, msg_type)?;
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
        let msg_type = decode_mctp_header(rsp)?;
        let expected_msg_type = self
            .mctp
            .msg_type()
            .map_err(|_| TransportError::UnexpectedMessageType)?;

        if msg_type != expected_msg_type {
            return Err(TransportError::UnexpectedMessageType);
        }

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
        let msg_type = decode_mctp_header(req)?;

        if msg_type
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
        encode_mctp_header(resp, msg_type)?;

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
