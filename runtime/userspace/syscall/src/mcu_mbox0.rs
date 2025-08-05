// Licensed under the Apache-2.0 license

//! # MCU Mailbox 0 Interface (Receiver Mode)

use crate::DefaultSyscalls;
use core::{hint::black_box, marker::PhantomData};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

static MCU_MBOX0_MUTEX: Mutex<CriticalSectionRawMutex, u32> = Mutex::new(0);

/// MCU Mailbox 0 interface (receiver mode)
pub struct McuMbox0<S: Syscalls = DefaultSyscalls> {
    _syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Default for McuMbox0<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> McuMbox0<S> {
    pub fn new() -> Self {
        Self {
            _syscall: PhantomData,
            driver_num: MCU_MBOX0_DRIVER_NUM,
        }
    }

    /// Waits asynchronously for a mailbox command and its data payload.
    ///
    /// Fills the provided buffer with the received data payload and returns the command ID and data length.
    pub async fn receive_command(&self, buffer: &mut [u8]) -> Result<(u32, usize), McuMbox0Error> {
        let result = {
            let mutex = MCU_MBOX0_MUTEX.lock().await;
            let result = share::scope::<(), _, _>(|_handle| {
                let mut sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                    self.driver_num,
                    mcu_mbox0_subscribe::REQUEST_RECEIVED,
                    mcu_mbox0_rw_buffer::REQUEST,
                    buffer,
                );
                match S::command(self.driver_num, mcu_mbox0_cmd::RECEIVE_REQUEST, 0, 0)
                    .to_result::<(), ErrorCode>()
                {
                    Ok(()) => Ok(TockSubscribe::subscribe_finish(sub)),
                    Err(err) => {
                        S::unallow_rw(self.driver_num, mcu_mbox0_rw_buffer::REQUEST);
                        sub.cancel();
                        Err(McuMbox0Error::ErrorCode(err))
                    }
                }
            })?
            .await;
            black_box(*mutex);
            result
        };
        match result {
            Ok((bytes, error_code, command)) => {
                if error_code != 0 {
                    Err(McuMbox0Error::MailboxError(error_code))
                } else {
                    Ok((command, bytes as usize))
                }
            }
            Err(err) => Err(McuMbox0Error::ErrorCode(err)),
        }
    }

    /// Sends response to the mailbox host asynchronously.
    /// Returns the number of bytes sent, or an error.
    pub async fn send_response(&self, buffer: &[u8]) -> Result<usize, McuMbox0Error> {
        let result = {
            let mutex = MCU_MBOX0_MUTEX.lock().await;
            let result = share::scope::<(), _, _>(|_handle| {
                let mut sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                    self.driver_num,
                    mcu_mbox0_subscribe::RESPONSE_SENT,
                    mcu_mbox0_ro_buffer::RESPONSE,
                    buffer,
                );
                match S::command(
                    self.driver_num,
                    mcu_mbox0_cmd::SEND_RESPONSE,
                    0,
                    buffer.len() as u32,
                )
                .to_result::<(), ErrorCode>()
                {
                    Ok(()) => Ok(TockSubscribe::subscribe_finish(sub)),
                    Err(err) => {
                        S::unallow_ro(self.driver_num, mcu_mbox0_ro_buffer::RESPONSE);
                        sub.cancel();
                        Err(McuMbox0Error::ErrorCode(err))
                    }
                }
            })?
            .await;
            black_box(*mutex);
            result
        };
        match result {
            Ok((bytes, error_code, _)) => {
                if error_code != 0 {
                    Err(McuMbox0Error::MailboxError(error_code))
                } else {
                    Ok(bytes as usize)
                }
            }
            Err(err) => Err(McuMbox0Error::ErrorCode(err)),
        }
    }
}

// -----------------------------------------------------------------------------
// Command IDs and MCU Mailbox 0-specific constants
// -----------------------------------------------------------------------------

pub const MCU_MBOX0_DRIVER_NUM: u32 = 0x8000_0010;

mod mcu_mbox0_cmd {
    pub const RECEIVE_REQUEST: u32 = 1;
    pub const SEND_RESPONSE: u32 = 2;
}

// Read-only buffer to read the response from.
mod mcu_mbox0_ro_buffer {
    pub const RESPONSE: u32 = 0;
}

// Read-write buffer to write the received request to.
mod mcu_mbox0_rw_buffer {
    pub const REQUEST: u32 = 0;
}

mod mcu_mbox0_subscribe {
    pub const REQUEST_RECEIVED: u32 = 0;
    pub const RESPONSE_SENT: u32 = 1;
}

#[derive(Debug, PartialEq)]
pub enum McuMbox0Error {
    ErrorCode(ErrorCode),
    MailboxError(u32),
}
