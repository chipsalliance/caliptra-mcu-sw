// Licensed under the Apache-2.0 license

use crate::DefaultSyscalls;
use core::{hint::black_box, marker::PhantomData};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

static MCU_MBOX_MUTEX: Mutex<CriticalSectionRawMutex, u32> = Mutex::new(0);
pub type CmdCode = u32;

pub struct McuMbox<S: Syscalls = DefaultSyscalls> {
    _syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Default for McuMbox<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> McuMbox<S> {
    /// Creates a new instance of MCU mailbox.
    ///
    /// # Arguments
    ///
    /// * `driver_num` - The driver number associated with the MCU mailbox.
    ///
    /// # Returns
    /// A new instance of `McuMbox`.
    pub fn new() -> Self {
        Self {
            _syscall: PhantomData,
            driver_num: MCU_MBOX0_DRIVER_NUM,
        }
    }

    /// Checks if the MCU mailbox driver is available.
    ///
    /// # Returns
    /// - `true` if the driver is available, `false` otherwise.
    pub fn exists(&self) -> bool {
        S::command(self.driver_num, command::EXISTS, 0, 0).is_success()
    }

    /// Receives a command from the MCU mailbox sender asynchronously (receiver mode).
    ///
    /// # Arguments
    ///
    /// * `data` - A mutable byte slice to store the received command data.
    ///
    /// # Returns
    ///
    /// Returns a tuple containing the command code and the number of bytes received,
    /// or an error if the operation fails.
    pub async fn receive_command(&self, data: &mut [u8]) -> Result<(CmdCode, usize), ErrorCode> {
        if data.is_empty() {
            return Err(ErrorCode::Invalid);
        }

        let mutex = MCU_MBOX_MUTEX.lock().await;
        let (command, recv_len, _) = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                subscribe::REQUEST_RECEIVED,
                allow_rw::REQUEST,
                data,
            );

            if let Err(e) = S::command(self.driver_num, command::RECEIVE_REQUEST, 0, 0)
                .to_result::<(), ErrorCode>()
            {
                sub.cancel();
                Err(e)?;
            }

            Ok(TockSubscribe::subscribe_finish(sub))
        })?
        .await?;

        black_box(*mutex); // Ensure the mutex is not optimized away

        Ok((command, recv_len as usize))
    }

    /// Sends a response to the MCU mailbox sender asynchronously (receiver mode).
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice containing the response data to send.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes sent, or an error if the operation fails.
    pub async fn send_response(&self, data: &[u8]) -> Result<usize, ErrorCode> {
        if data.is_empty() {
            return Err(ErrorCode::Invalid);
        }

        let mutex = MCU_MBOX_MUTEX.lock().await;
        let (sent_len, _, _) = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                subscribe::RESPONSE_SENT,
                allow_ro::RESPONSE,
                data,
            );

            if let Err(e) = S::command(self.driver_num, command::SEND_RESPONSE, 0, 0)
                .to_result::<(), ErrorCode>()
            {
                S::unallow_ro(self.driver_num, allow_ro::RESPONSE);
                sub.cancel();
                Err(e)?;
            }

            Ok(TockSubscribe::subscribe_finish(sub))
        })?
        .await?;

        black_box(*mutex);

        Ok(sent_len as usize)
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

pub const MCU_MBOX0_DRIVER_NUM: u32 = 0x8000_0010;

/// Command IDs
/// - `0` - Command to check if the MCU mailbox syscall driver exists
/// - `1` - Receive request
/// - `2` - Receive response
mod command {
    pub const EXISTS: u32 = 0;
    pub const RECEIVE_REQUEST: u32 = 1;
    pub const SEND_RESPONSE: u32 = 2;
}

// Read-only buffer to read the response from.
mod allow_ro {
    pub const RESPONSE: u32 = 0;
}

// Read-write buffer to write the received request to.
mod allow_rw {
    pub const REQUEST: u32 = 0;
}

// Upcalls
mod subscribe {
    pub const REQUEST_RECEIVED: u32 = 0;
    pub const RESPONSE_SENT: u32 = 1;
}
