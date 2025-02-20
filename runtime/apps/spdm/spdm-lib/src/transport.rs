// Licensed under the Apache-2.0 license

use thiserror_no_std::Error;

use crate::message_buf::MessageBuf;
use core::fmt::Write;
use libsyscall_caliptra::mctp::{driver_num, Mctp, MessageInfo};
use libtock_console::Console;
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};

pub type TransportResult<T> = Result<T, TransportError>;

pub enum SpdmTransportType {
    Mctp,
}

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("MCTP driver Error")]
    MctpDriverError,
    #[error("Buffer too small")]
    BufferTooSmall,
    #[error("Invalid argument")]
    InvalidArgument,
    #[error("Unexpected message type received")]
    UnexpectedMessageType,
    #[error("Message receive error")]
    ReceiveError,
    #[error("Message send error")]
    SendError,
    #[error("Response is not expected")]
    ResponseNotExpected,
    #[error("No request in flight")]
    NoRequestInFlight,
}

pub struct MctpTransport<S: Syscalls> {
    mctp: Mctp<S>,
    cur_resp_ctx: Option<MessageInfo>,
    cur_req_ctx: Option<u8>,
}

impl<S: Syscalls> MctpTransport<S> {
    pub fn new(drv_num: u32) -> Self {
        Self {
            mctp: Mctp::<S>::new(drv_num),
            cur_resp_ctx: None,
            cur_req_ctx: None,
        }
    }

    pub async fn send_request(&mut self, dest_eid: u8, req: &[u8]) -> TransportResult<()> {
        let tag = self
            .mctp
            .send_request(dest_eid, req)
            .await
            .map_err(|_| TransportError::SendError)?;

        self.cur_req_ctx = Some(tag);

        Ok(())
    }

    pub async fn receive_response(&mut self, msg: &mut [u8]) -> TransportResult<usize> {
        let (recv_len, _msg_info) = if let Some(tag) = self.cur_req_ctx {
            self.mctp
                .receive_response(msg, tag)
                .await
                .map_err(|_| TransportError::ReceiveError)
        } else {
            Err(TransportError::ResponseNotExpected)
        }?;
        self.cur_req_ctx = None;
        Ok(recv_len as usize)
    }

    pub async fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<()> {
        req.reset();
        let mut console_writer = Console::<S>::writer();

        let max_len = req.capacity();
        req.put_data(max_len)
            .map_err(|_| TransportError::BufferTooSmall)?;

        let data_buf = req
            .data_mut(max_len)
            .map_err(|_| TransportError::BufferTooSmall)?;

        // writeln!(
        //     console_writer,
        //     "MCTP:2 Receive request might have panicked before here"
        // )
        // .unwrap();

        let (msg_len, msg_info) = self
            .mctp
            .receive_request(data_buf)
            .await
            .map_err(|_| TransportError::ReceiveError)?;

        writeln!(
            console_writer,
            "MCTP:2 Received request, msg_len{}",
            msg_len
        )
        .unwrap();

        if msg_len == 0 {
            writeln!(console_writer, "MCTP:3 buffer too small").unwrap();
            Err(TransportError::BufferTooSmall)?;
        }

        // Set the length of the message
        req.trim(msg_len as usize)
            .map_err(|_| TransportError::BufferTooSmall)?;

        // Process the transport message header
        let header = req.data(1).map_err(|_| TransportError::BufferTooSmall)?;
        if header[0]
            != self
                .mctp
                .msg_type()
                .map_err(|_| TransportError::UnexpectedMessageType)?
        {
            Err(TransportError::UnexpectedMessageType)?;
        }

        req.pull_data(1)
            .map_err(|_| TransportError::BufferTooSmall)?;

        self.cur_resp_ctx = Some(msg_info);

        writeln!(console_writer, "MCTP:4 Received request").unwrap();

        Ok(())
    }

    pub async fn send_response<'a>(&mut self, resp: &mut MessageBuf<'a>) -> TransportResult<()> {
        // push data to make room for the transport message header
        resp.push_data(1)
            .map_err(|_| TransportError::BufferTooSmall)?;

        // Set the transport message header
        let header = resp
            .data_mut(1)
            .map_err(|_| TransportError::BufferTooSmall)?;
        header[0] = self
            .mctp
            .msg_type()
            .map_err(|_| TransportError::InvalidArgument)?;

        let msg_len = resp.len();
        let rsp_buf = resp
            .data(msg_len)
            .map_err(|_| TransportError::BufferTooSmall)?;
        writeln!(
            Console::<S>::writer(),
            "MCTP: Transport Sending response, resp_len {} resp {:?}",
            msg_len,
            rsp_buf,
        )
        .unwrap();

        if let Some(msg_info) = self.cur_resp_ctx.clone() {
            self.mctp
                .send_response(&resp[..msg_len], msg_info)
                .await
                .map_err(|_| TransportError::SendError)?
        } else {
            Err(TransportError::NoRequestInFlight)?;
        }

        self.cur_resp_ctx = None;

        Ok(())
    }

    pub fn max_message_size(&self) -> TransportResult<usize> {
        let max_size = self
            .mctp
            .max_message_size()
            .map_err(|_| TransportError::MctpDriverError)?;
        Ok(max_size as usize - self.header_size())
    }

    pub fn header_size(&self) -> usize {
        1
    }
}
