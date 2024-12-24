// Licensed under the Apache-2.0 license

#![no_std]
use core::cell::Cell;
use libtock_platform::allow_ro::AllowRo;
use libtock_platform::allow_rw::AllowRw;
use libtock_platform::share;
use libtock_platform::subscribe::Subscribe;
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

use core::fmt::Write;
use libtock_console::Console;

#[derive(Debug)]
pub struct MessageInfo {
    pub eid: u8,
    pub msg_tag: u8,
    pub msg_type: u8,
    pub recv_time: u32,
    pub payload_len: usize,
}

pub mod message_type {
    pub const SPDM: u8 = 0x5;
    pub const SECURE_SPDM: u8 = 0x6;
    pub const PLDM: u8 = 0x1;
    pub const VENDOR_DEFINED_PCI: u8 = 0x7E;
    pub const ANY_SUPPORTED: u8 = 0xFF; // Receive any supported message type
}

pub struct AsyncMctp<const DRIVER_NUM: u32, S: Syscalls, C: Config = DefaultConfig>(S, C);

macro_rules! eid {
    ($msg_info:expr) => {
        (($msg_info & 0xFF0000) >> 16) as u8
    };
}

macro_rules! msg_tag {
    ($msg_info:expr) => {
        ($msg_info & 0x07) as u8
    };
}

macro_rules! msg_type {
    ($msg_info:expr) => {
        (($msg_info & 0xFF00) >> 8) as u8
    };
}

impl<const DRIVER_NUM: u32, S: Syscalls, C: Config> AsyncMctp<DRIVER_NUM, S, C> {
    /// Check if the MCTP driver for a specific message type exists
    ///
    /// # Returns
    /// * `bool` - `true` if the driver exists, `false` otherwise
    pub fn exists() -> bool {
        S::command(DRIVER_NUM, command::EXISTS, 0, 0).is_success()
    }

    pub fn receive_request_sync(
        source_eid: u8,
        msg_type: Option<u8>,
        msg_payload: &mut [u8],
    ) -> Result<MessageInfo, ErrorCode> {
        let called: Cell<Option<(u32, u32, u32)>> = Cell::new(None);
        let mut console_writer = Console::<S>::writer();
        let msg_type = if let Some(msg_type) = msg_type {
            AsyncMctp::<DRIVER_NUM, S, C>::supported_message_type(msg_type)?;
            msg_type
        } else {
            message_type::ANY_SUPPORTED
        };

        if msg_payload.is_empty() {
            writeln!(console_writer, "USER: Empty buffer!!!!").unwrap();
            return Err(ErrorCode::Invalid);
        }
        writeln!(console_writer, "USER payload size {}", msg_payload.len()).unwrap();

        let msg_tag: u32 = MCTP_TAG_OWNER as u32;
        let msg_info = msg_tag << 8 | msg_type as u32;

        share::scope::<
            (
                AllowRw<_, { DRIVER_NUM }, { allow_rw::MESSAGE_READ }>,
                Subscribe<_, { DRIVER_NUM }, { subscribe::MESSAGE_RECEIVED }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_rw, subscribe) = handle.split();
            S::allow_rw::<C, DRIVER_NUM, { allow_rw::MESSAGE_READ }>(allow_rw, msg_payload)?;
            S::subscribe::<_, _, C, DRIVER_NUM, { subscribe::MESSAGE_RECEIVED }>(
                subscribe, &called,
            )?;

            // let sub = TockSubscribe::subscribe::<S>(DRIVER_NUM, subscribe::MESSAGE_RECEIVED);

            S::command(
                DRIVER_NUM,
                command::RECEIVE_REQUEST,
                source_eid as u32,
                msg_info,
            )
            .to_result::<(), ErrorCode>()?;

            loop {
                S::yield_wait();
                if let Some((msg_len, recv_time, msg_info)) = called.get() {
                    return Ok(MessageInfo {
                        eid: eid!(msg_info),
                        msg_tag: msg_tag!(msg_info),
                        msg_type: msg_type!(msg_info),
                        recv_time,
                        payload_len: msg_len as usize,
                    });
                }
            }
        })
    }

    pub fn send_response_sync(
        dest_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        msg_payload: &[u8],
    ) -> Result<(), ErrorCode> {
        let called: Cell<Option<(u32, u32, u32)>> = Cell::new(None);
        AsyncMctp::<DRIVER_NUM, S, C>::supported_message_type(msg_type)?;

        let msg_info = (msg_tag as u32) << 8 | msg_type as u32;

        share::scope::<
            (
                AllowRo<_, DRIVER_NUM, { allow_ro::MESSAGE_WRITE }>,
                Subscribe<_, DRIVER_NUM, { subscribe::MESSAGE_TRANSMITTED }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_ro, subscribe) = handle.split();
            S::allow_ro::<C, { DRIVER_NUM }, { allow_ro::MESSAGE_WRITE }>(allow_ro, msg_payload)?;

            S::subscribe::<_, _, C, DRIVER_NUM, { subscribe::MESSAGE_TRANSMITTED }>(
                subscribe, &called,
            )?;

            S::command(
                DRIVER_NUM,
                command::SEND_RESPONSE,
                dest_eid as u32,
                msg_info,
            )
            .to_result::<(), ErrorCode>()?;

            loop {
                S::yield_wait();
                if let Some((result, _, _)) = called.get() {
                    return match result {
                        0 => Ok(()),
                        _ => Err(result.try_into().unwrap_or(ErrorCode::Fail)),
                    };
                }
            }
        })
    }

    /// Receive the MCTP request from the source EID
    ///
    /// # Arguments
    /// * `source_eid` - The source EID from which the request is to be received.
    /// * `msg_type` - The message type to receive. If `None`, the function receives all message types supported by the driver.
    /// * `msg_payload` - The buffer to store the received message payload
    ///
    /// # Returns
    /// * `MessageInfo` - The message information containing the EID, message tag, message type, and payload length on success
    /// * `ErrorCode` - The error code on failure
    pub async fn receive_request(
        source_eid: u8,
        msg_type: Option<u8>,
        msg_payload: &mut [u8],
    ) -> Result<MessageInfo, ErrorCode> {
        let mut console_writer = Console::<S>::writer();
        let msg_type = if let Some(msg_type) = msg_type {
            AsyncMctp::<DRIVER_NUM, S, C>::supported_message_type(msg_type)?;
            msg_type
        } else {
            message_type::ANY_SUPPORTED
        };

        if msg_payload.is_empty() {
            writeln!(console_writer, "USER: Empty buffer!!!!").unwrap();
            return Err(ErrorCode::Invalid);
        }
        writeln!(console_writer, "USER payload size {}", msg_payload.len()).unwrap();

        let msg_tag: u32 = MCTP_TAG_OWNER as u32;
        let msg_info = msg_tag << 8 | msg_type as u32;

        let sub = share::scope::<(), _, _>(
            |_handle| {

                let sub = TockSubscribe::subscribe_allow_rw::<S, C>(DRIVER_NUM, subscribe::MESSAGE_RECEIVED, allow_rw::MESSAGE_READ, msg_payload);

                S::command(
                    DRIVER_NUM,
                    command::RECEIVE_REQUEST,
                    source_eid as u32,
                    msg_info,
                )
                .to_result::<(), ErrorCode>()?;

                Ok(sub)
            },
        )?;

        writeln!(console_writer, "USER: AWAIT in Receive request").unwrap();
        let (msg_len, recv_time, msg_info) = sub.await?;
        Ok(MessageInfo {
            eid: eid!(msg_info),
            msg_tag: msg_tag!(msg_info),
            msg_type: msg_type!(msg_info),
            recv_time: recv_time,
            payload_len: msg_len as usize,
        })
    }

    // sub.await.map(|(msg_len, src_eid, msg_info)| {
    //     Ok(MessageInfo {
    //         eid: src_eid as u8,
    //         msg_tag: (msg_info & 0xFF) as u8,
    //         msg_type: (msg_info >> 8) as u8,
    //         payload_len: msg_len as usize,
    //     })
    // })?

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
    pub async fn send_response(
        dest_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        msg_payload: &[u8],
    ) -> Result<(), ErrorCode> {
        AsyncMctp::<DRIVER_NUM, S, C>::supported_message_type(msg_type)?;

        let msg_info = (msg_tag as u32) << 8 | msg_type as u32;

        let sub = share::scope::<(), _, _>(
            |_handle| {
                // let allow_ro = handle.split()V.0;
                // S::allow_ro::<C, { DRIVER_NUM }, { allow_ro::MESSAGE_WRITE }>(
                //     allow_ro,
                //     msg_payload,
                // )?;

                let sub = TockSubscribe::subscribe_allow_ro::<S, C>(DRIVER_NUM, subscribe::MESSAGE_TRANSMITTED, allow_ro::MESSAGE_WRITE, msg_payload);

                S::command(
                    DRIVER_NUM,
                    command::SEND_RESPONSE,
                    dest_eid as u32,
                    msg_info,
                )
                .to_result::<(), ErrorCode>()?;

                Ok(sub)
            },
        )?;

        sub.await.map(|(result, _, _)| match result {
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
    pub async fn send_request(
        msg_type: u8,
        dest_eid: u8,
        msg_payload: &[u8],
    ) -> Result<u8, ErrorCode> {
        AsyncMctp::<DRIVER_NUM, S, C>::supported_message_type(msg_type)?;

        let sub = share::scope::<(), _, _>(
            |_handle| {
                // let allow_ro = handle.split().0;
                // S::allow_ro::<C, { DRIVER_NUM }, { allow_ro::MESSAGE_WRITE }>(
                //     allow_ro,
                //     msg_payload,
                // )?;

                let sub = TockSubscribe::subscribe_allow_ro::<S, C>(DRIVER_NUM, subscribe::MESSAGE_TRANSMITTED, allow_ro::MESSAGE_WRITE, msg_payload);

                S::command(
                    DRIVER_NUM,
                    command::SEND_REQUEST,
                    dest_eid as u32,
                    msg_type as u32,
                )
                .to_result::<(), ErrorCode>()?;

                Ok(sub)
            },
        )?;

        sub.await
            .map(|(result, _dest_eid, msg_info)| match result {
                0 => Ok(((msg_info >> 8) & 0xFF) as u8),
                _ => Err(result.try_into().unwrap_or(ErrorCode::Fail)),
            })?
    }

    /// Receive the MCTP response from the source EID
    ///
    /// # Arguments
    /// * `source_eid` - The source EID from which the response is to be received
    /// * `msg_type` - The message type to receive. This is needed for SPDM to differentiate between SPDM(0x5) and secured SPDM(0x6) messages
    /// * `msg_tag` - The message tag assigned to the request
    /// * `msg_payload` - The buffer to store the received response payload
    ///
    /// # Returns
    /// * `()` - On success
    /// * `ErrorCode` - The error code on failure
    pub async fn receive_response(
        source_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        msg_payload: &mut [u8],
    ) -> Result<MessageInfo, ErrorCode> {
        AsyncMctp::<DRIVER_NUM, S, C>::supported_message_type(msg_type)?;

        let msg_info = (msg_tag << 8) as u32 | msg_type as u32;

        let sub = share::scope::<
            (
                // AllowRw<_, { DRIVER_NUM }, { allow_rw::MESSAGE_READ }>,
                // Subscribe<_, { DRIVER_NUM }, { subscribe::MESSAGE_RECEIVED }>,
            ),
            _,
            _,
        >(|_handle| {
            // let allow_rw = handle.split().0;
            // S::allow_rw::<C, DRIVER_NUM, { allow_rw::MESSAGE_READ }>(allow_rw, msg_payload)?;

            let sub = TockSubscribe::subscribe_allow_rw::<S, C>(DRIVER_NUM, subscribe::MESSAGE_RECEIVED, allow_rw::MESSAGE_READ, msg_payload);

            S::command(
                DRIVER_NUM,
                command::RECEIVE_RESPONSE,
                source_eid as u32,
                msg_info,
            )
            .to_result::<(), ErrorCode>()?;

            Ok(sub)
        })?;

        sub.await
            .map(|(msg_len, recv_time, msg_info)| {
                Ok(MessageInfo {
                    eid: ((msg_info & 0xFF0000) >> 16) as u8,
                    msg_tag: (msg_info & 0xFF) as u8,
                    msg_type: (msg_info >> 8) as u8,
                    recv_time,
                    payload_len: msg_len as usize,
                })
            })
            .map_err(|_| ErrorCode::Fail)?
    }

    pub fn get_max_message_size() -> Result<u32, ErrorCode> {
        S::command(DRIVER_NUM, command::GET_MAX_MESSAGE_SIZE, 0, 0).to_result()
    }

    fn supported_message_type(msg_type: u8) -> Result<(), ErrorCode> {
        match DRIVER_NUM {
            driver_num::MCTP_SPDM => {
                if msg_type == message_type::SPDM || msg_type == message_type::SECURE_SPDM {
                    Ok(())
                } else {
                    Err(ErrorCode::Invalid)
                }
            }
            driver_num::MCTP_PLDM => {
                if msg_type == message_type::PLDM || msg_type == message_type::ANY_SUPPORTED {
                    Ok(())
                } else {
                    Err(ErrorCode::Invalid)
                }
            }
            driver_num::MCTP_VENDOR_DEFINED_PCI => {
                if msg_type == message_type::VENDOR_DEFINED_PCI
                    || msg_type == message_type::ANY_SUPPORTED
                {
                    Ok(())
                } else {
                    Err(ErrorCode::Invalid)
                }
            }
            _ => Err(ErrorCode::Invalid),
        }
    }
}

/// System call configuration trait for `mctp`.
pub trait Config:
    libtock_platform::allow_ro::Config
    + libtock_platform::allow_rw::Config
    + libtock_platform::subscribe::Config
{
}
impl<
        T: libtock_platform::allow_ro::Config
            + libtock_platform::allow_rw::Config
            + libtock_platform::subscribe::Config,
    > Config for T
{
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

const MCTP_TAG_OWNER: u8 = 0x08;

pub mod driver_num {
    pub const MCTP_SPDM: u32 = 0xA0000;
    pub const MCTP_PLDM: u32 = 0xA0001;
    pub const MCTP_VENDOR_DEFINED_PCI: u32 = 0xA0002;
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
