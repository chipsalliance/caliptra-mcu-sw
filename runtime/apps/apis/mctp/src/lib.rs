// Licensed under the Apache-2.0 license

#![no_std]
use core::marker::PhantomData;
use libtock_platform::share;
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

use core::fmt::Write;
use libtock_console::Console;

type EndpointId = u8;
type Tag = u8;

#[derive(Debug)]
pub struct MessageInfo {
    eid: EndpointId,
    tag: Tag,
}

// impl from u32 for MessageInfo
impl From<u32> for MessageInfo {
    fn from(msg_info: u32) -> Self {
        MessageInfo {
            eid: ((msg_info & 0xFF0000) >> 16) as u8,
            tag: (msg_info & 0xFF) as u8,
        }
    }
}

pub mod message_type {
    pub const SPDM: u8 = 0x5;
    pub const SECURE_SPDM: u8 = 0x6;
    pub const PLDM: u8 = 0x1;
    pub const CALIPTRA: u8 = 0x7E;
    pub const ANY_SUPPORTED: u8 = 0xFF; // Receive any supported message type
}

pub struct Mctp<S: Syscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Mctp<S> {
    /// Create a new instance of the MCTP driver
    ///
    /// # Arguments
    /// * `driver_num` - The driver number for the MCTP driver
    ///
    /// # Returns
    /// * `AsyncMctp` - The MCTP driver instance
    pub fn new(driver_num: u32) -> Self {
        Self {
            syscall: PhantomData,
            driver_num,
        }
    }
    /// Check if the MCTP driver for a specific message type exists
    ///
    /// # Returns
    /// * `bool` - `true` if the driver exists, `false` otherwise
    pub fn exists(&self) -> bool {
        S::command(self.driver_num, command::EXISTS, 0, 0).is_success()
    }

    /// Receive the MCTP request from the source EID
    ///
    /// # Arguments
    /// * `msg_payload` - The buffer to store the received message payload
    ///
    /// # Returns
    /// * `MessageInfo` - The message information containing the EID, message tag, message type, and payload length on success
    /// * `ErrorCode` - The error code on failure
    pub async fn receive_request(&self, req: &mut [u8]) -> Result<(u32, MessageInfo), ErrorCode> {
        let mut console_writer = Console::<S>::writer();

        if req.is_empty() {
            writeln!(console_writer, "USER: Empty buffer!!!!").unwrap();
            return Err(ErrorCode::Invalid);
        }
        writeln!(console_writer, "USER payload size {}", req.len()).unwrap();

        let (recv_len, _, info) = share::scope::<(), _, _>(|_handle| {
            let sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                subscribe::MESSAGE_RECEIVED,
                allow_rw::MESSAGE_READ,
                req,
            );

            S::command(self.driver_num, command::RECEIVE_REQUEST, 0, 0)
                .to_result::<(), ErrorCode>()?;

            Ok(sub)
        })?
        .await?;

        Ok((recv_len, info.into()))
    }

    /// Send the MCTP response to the destination EID
    ///
    /// # Arguments
    /// * `dest_eid` - The destination EID to which the response is to be sent
    /// * `msg_tag` - The message tag assigned to the request
    /// * `msg_payload` - The payload to be sent in the response
    ///
    /// # Returns
    /// * `()` - On success
    /// * `ErrorCode` - The error code on failure
    pub async fn send_response(&self, resp: &[u8], info: MessageInfo) -> Result<(), ErrorCode> {
        let ro_sub = share::scope::<(), _, _>(|_handle| {
            let ro_sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                subscribe::MESSAGE_TRANSMITTED,
                allow_ro::MESSAGE_WRITE,
                resp,
            );

            S::command(
                self.driver_num,
                command::SEND_RESPONSE,
                info.eid as u32,
                info.tag as u32,
            )
            .to_result::<(), ErrorCode>()?;

            Ok(ro_sub)
        })?;

        ro_sub.await.map(|(result, _, _)| match result {
            0 => Ok(()),
            _ => Err(result.try_into().unwrap_or(ErrorCode::Fail)),
        })?
    }

    /// Send the MCTP request to the destination EID
    /// The function returns the message tag assigned to the request.
    ///
    /// # Arguments
    /// * `msg_type` - The message type to send. This is needed for SPDM to differentiate between SPDM(0x5) and secured SPDM(0x6) messages
    /// * `dest_eid` - The destination EID to which the request is to be sent
    /// * `msg_payload` - The payload to be sent in the request
    ///
    /// # Returns
    /// * `u8` - The message tag assigned to the request
    /// * `ErrorCode` - The error code on failure
    pub async fn send_request(&self, dest_eid: u8, req: &[u8]) -> Result<Tag, ErrorCode> {
        let (result, _, info) = share::scope::<(), _, _>(|_handle| {
            let sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                subscribe::MESSAGE_TRANSMITTED,
                allow_ro::MESSAGE_WRITE,
                req,
            );

            S::command(
                self.driver_num,
                command::SEND_REQUEST,
                dest_eid as u32,
                MCTP_TAG_OWNER as u32,
            )
            .to_result::<(), ErrorCode>()?;

            Ok(sub)
        })?
        .await?;

        let info: MessageInfo = info.into();

        match result {
            0 => Ok(info.tag),
            _ => Err(result.try_into().unwrap_or(ErrorCode::Fail)),
        }
    }

    /// Receive the MCTP response from the source EID
    ///
    /// # Arguments
    /// * `source_eid` - The source EID from which the response is to be received
    /// * `msg_tag` - The message tag assigned to the request
    /// * `msg_payload` - The buffer to store the received response payload
    ///
    /// # Returns
    /// * `()` - On success
    /// * `ErrorCode` - The error code on failure
    pub async fn receive_response(
        &self,
        msg_tag: u8,
        msg_payload: &mut [u8],
    ) -> Result<(u32, MessageInfo), ErrorCode> {
        let (recv_len, _, info) = share::scope::<(), _, _>(|_handle| {
            let sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                subscribe::MESSAGE_RECEIVED,
                allow_rw::MESSAGE_READ,
                msg_payload,
            );

            S::command(
                self.driver_num,
                command::RECEIVE_RESPONSE,
                0,
                msg_tag as u32,
            )
            .to_result::<(), ErrorCode>()?;

            Ok(sub)
        })?
        .await?;

        Ok((recv_len, info.into()))
    }

    pub fn max_message_size(&self) -> Result<u32, ErrorCode> {
        S::command(self.driver_num, command::GET_MAX_MESSAGE_SIZE, 0, 0).to_result()
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

const MCTP_TAG_OWNER: u8 = 0x08;

pub mod driver_num {
    pub const MCTP_SPDM: u32 = 0xA0000;
    pub const MCTP_SECURE: u32 = 0xA0001;
    pub const MCTP_PLDM: u32 = 0xA0002;
    pub const MCTP_CALIPTRA: u32 = 0xA0003;
}

// Command IDs
/// - `0` - Command to check if the MCTP driver exists
/// - `1` - Receive MCTP request
/// - `2` - Receive MCTP response
/// - `3` - Send MCTP request
/// - `4` - Send MCTP response
/// - `5` - Get maximum message size supported by the MCTP driver
mod command {
    pub const EXISTS: u32 = 0;
    pub const RECEIVE_REQUEST: u32 = 1;
    pub const RECEIVE_RESPONSE: u32 = 2;
    pub const SEND_REQUEST: u32 = 3;
    pub const SEND_RESPONSE: u32 = 4;
    pub const GET_MAX_MESSAGE_SIZE: u32 = 5;
}

mod subscribe {
    /// Message received
    pub const MESSAGE_RECEIVED: u32 = 0;
    /// Message transmitted
    pub const MESSAGE_TRANSMITTED: u32 = 1;
}

mod allow_ro {
    /// Write buffer for the message payload to be transmitted
    pub const MESSAGE_WRITE: u32 = 0;
}

mod allow_rw {
    /// Read buffer for the message payload received
    pub const MESSAGE_READ: u32 = 0;
}
