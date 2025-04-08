// Licensed under the Apache-2.0 license

use core::marker::PhantomData;
use libtock_platform::share;
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

use core::fmt::Write;
use libtock_console::Console;

type EndpointId = u8;
type Tag = u8;

#[derive(Debug, Clone)]
pub struct MessageInfo {
    eid: EndpointId,
    tag: Tag,
}

impl From<u32> for MessageInfo {
    fn from(msg_info: u32) -> Self {
        MessageInfo {
            eid: ((msg_info & 0xFF0000) >> 16) as u8,
            tag: (msg_info & 0xFF) as u8,
        }
    }
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
    /// * `Mctp` - The MCTP driver instance
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

    /// Receive the MCTP request.
    /// Receives a message from any source EID. The user should use the returned MessageInfo to send a response.
    ///
    /// # Arguments
    /// * `req` - The buffer to store the received request payload
    ///
    /// # Returns
    /// * `(u32, MessageInfo)` - On success, returns tuple containing length of the request received and the message information containing the source EID, message tag
    /// * `ErrorCode` - The error code on failure
    pub async fn receive_request(&self, req: &mut [u8]) -> Result<(u32, MessageInfo), ErrorCode> {
        let mut console_writer = Console::<S>::writer();
        if req.is_empty() {
            writeln!(console_writer, "MCTP: received empty req").unwrap();
            Err(ErrorCode::Invalid)?;
        }

        let (recv_len, _, info) = share::scope::<(), _, _>(|_handle| {
            let sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                subscribe::RECEIVED_REQUEST,
                allow_rw::READ_REQUEST,
                req,
            );

            S::command(self.driver_num, command::RECEIVE_REQUEST, 0, 0)
                .to_result::<(), ErrorCode>()?;

            Ok(sub)
        })?
        .await?;

        Ok((recv_len, info.into()))
    }

    /// Send the MCTP response to an endpoint
    ///
    /// # Arguments
    /// * `resp` - The buffer containing the response payload
    /// * `info` - The message information containing the destination EID, message tag which was received in `receive_request` call
    ///
    /// # Returns
    /// * `()` - On success
    /// * `ErrorCode` - The error code on failure
    pub async fn send_response(&self, resp: &[u8], info: MessageInfo) -> Result<(), ErrorCode> {
        let max_size = self.max_message_size()? as usize;

        if resp.is_empty() || resp.len() > max_size {
            Err(ErrorCode::Invalid)?;
        }

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
                (info.tag & 0x7) as u32,
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
    /// The function returns the message tag assigned to the request by the MCTP Capsule.
    /// This tag will be used in the `receive_response` call to receive the corresponding response.
    ///
    /// # Arguments
    /// * `dest_eid` - The destination EID to which the request is to be sent
    /// * `req` - The payload to be sent in the request
    ///
    /// # Returns
    /// * `Tag` - The message tag assigned to the request
    /// * `ErrorCode` - The error code on failure
    pub async fn send_request(&self, dest_eid: u8, req: &[u8]) -> Result<Tag, ErrorCode> {
        let max_size = self.max_message_size()? as usize;

        if req.is_empty() || req.len() > max_size {
            Err(ErrorCode::Invalid)?;
        }

        let (result, _, info) = share::scope::<(), _, _>(|_handle| {
            let sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                subscribe::MESSAGE_TRANSMITTED,
                allow_ro::MESSAGE_WRITE,
                req,
            );

            S::command(self.driver_num, command::SEND_REQUEST, dest_eid as u32, 0)
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

    /// Receive the MCTP response from an endpoint
    ///
    /// # Arguments
    /// * `resp` - The buffer to store the received response payload from the endpoint
    /// * `tag` - The message tag to match against the response message
    ///
    /// # Returns
    /// * `(u32, MessageInfo)` - On success, returns tuple containing length of the response received and the message information containing the source EID, message tag
    /// * `ErrorCode` - The error code on failure
    pub async fn receive_response(
        &self,
        resp: &mut [u8],
        tag: Tag,
    ) -> Result<(u32, MessageInfo), ErrorCode> {
        if resp.is_empty() || tag > 0x7 {
            Err(ErrorCode::Invalid)?;
        }

        let (recv_len, _, info) = share::scope::<(), _, _>(|_handle| {
            let sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                subscribe::RECEIVED_RESPONSE,
                allow_rw::READ_RESPONSE,
                resp,
            );

            S::command(self.driver_num, command::RECEIVE_RESPONSE, 0, tag as u32)
                .to_result::<(), ErrorCode>()?;

            Ok(sub)
        })?
        .await?;

        Ok((recv_len, info.into()))
    }

    pub fn max_message_size(&self) -> Result<u32, ErrorCode> {
        S::command(self.driver_num, command::GET_MAX_MESSAGE_SIZE, 0, 0).to_result()
    }

    pub fn msg_type(&self) -> Result<u8, ErrorCode> {
        match self.driver_num {
            driver_num::MCTP_SPDM => Ok(5),
            driver_num::MCTP_SECURE => Ok(6),
            driver_num::MCTP_PLDM => Ok(1),
            driver_num::MCTP_CALIPTRA => Ok(0x7E),
            _ => Err(ErrorCode::Invalid)?,
        }
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

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
    pub const RECEIVED_REQUEST: u32 = 0;
    pub const RECEIVED_RESPONSE: u32 = 1;
    /// Message transmitted
    pub const MESSAGE_TRANSMITTED: u32 = 2;
}

mod allow_ro {
    /// Write buffer for the message payload to be transmitted
    pub const MESSAGE_WRITE: u32 = 0;
}

mod allow_rw {
    /// Read buffer for the message payload received
    pub const READ_REQUEST: u32 = 0;
    pub const READ_RESPONSE: u32 = 1;
}
