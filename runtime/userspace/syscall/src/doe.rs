// Licensed under the Apache-2.0 license

use crate::DefaultSyscalls;
use core::marker::PhantomData;
use libtock_platform::share;
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

use core::fmt::Write;
use libtock_console::Console;

pub struct Doe<S: Syscalls = DefaultSyscalls> {
    _syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Doe<S> {
    /// Crates a new instance of the Doe driver interface.
    pub fn new(driver_num: u32) -> Self {
        Self {
            _syscall: PhantomData,
            driver_num,
        }
    }

    /// Checks if the DOE driver is available.
    ///
    /// # Returns
    /// - `true` if the driver is available, `false` otherwise.
    pub fn exists(&self) -> bool {
        S::command(self.driver_num, command::EXISTS, 0, 0).is_success()
    }

    /// Receives a DOE message.
    ///
    /// # Arguments
    /// - `buf` - A mutable buffer to store the received message.
    ///
    /// # Returns
    /// - `Ok(usize)` - The number of bytes received.
    /// - `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn receive_message(&self, buf: &mut [u8]) -> Result<u32, ErrorCode> {
        let mut cw = Console::<DefaultSyscalls>::writer();
        if buf.is_empty() {
            return Err(ErrorCode::Invalid);
        }

        let (recv_len, _, _) = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                subscribe::MESSAGE_RECEIVED,
                allow_rw::MESSAGE_READ,
                buf,
            );

            if let Err(e) = S::command(self.driver_num, command::RECEIVE_MESSAGE, 0, 0)
                .to_result::<(), ErrorCode>()
            {
                // Cancel the future if the command fails
                sub.cancel();
                Err(e)?;
            }

            Ok(TockSubscribe::subscribe_finish(sub))
        })?
        .await?;
        writeln!(
            cw,
            "SPDM_LIB: RECEIVE_MESSAGE: Upcall received for driver_num {:X}! recv_len = {}",
            self.driver_num, recv_len
        )
        .unwrap();

        Ok(recv_len)
    }

    /// Sends a DOE message.
    /// # Arguments
    /// - `buf` - A buffer containing the message to be sent.
    /// # Returns
    /// - `Ok(())` - If the message was sent successfully.
    /// - `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn send_message(&self, buf: &[u8]) -> Result<(), ErrorCode> {
        let mut cw = Console::<DefaultSyscalls>::writer();
        if buf.is_empty() {
            return Err(ErrorCode::Invalid);
        }

        let (_, _, _) = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                subscribe::MESSAGE_TRANSMITTED,
                allow_ro::MESSAGE_WRITE,
                buf,
            );

            if let Err(e) = S::command(self.driver_num, command::SEND_MESSAGE, 0, 0)
                .to_result::<(), ErrorCode>()
            {
                // Cancel the future if the command fails
                sub.cancel();
                Err(e)?;
            }

            Ok(TockSubscribe::subscribe_finish(sub))
        })?
        .await?;
        writeln!(
            cw,
            "SPDM_LIB: SEND_MESSAGE: Upcall received for driver_num {:X}! MESSAGE_TRANSMITTED",
            self.driver_num
        )
        .unwrap();

        Ok(())
    }

    /// Gets the maximum message size supported by the DOE transport layer.
    ///
    /// # Returns
    /// - `Ok(u32)` - The maximum message size in bytes.
    /// - `Err(ErrorCode)` - An error code if the operation fails.
    pub fn max_message_size(&self) -> Result<u32, ErrorCode> {
        S::command(self.driver_num, command::MAX_DATA_OBJECT_SIZE, 0, 0).to_result()
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

pub mod driver_num {
    pub const DOE_SPDM: u32 = 0xA000_0010;
}
/// Command IDs
/// - `0` - Command to check if the DOE driver exists
/// - `1` - Receive DOE message
/// - `2` - Receive DOE message
/// - `3` - Get maximum message size supported by the DOE transport layer
mod command {
    pub const EXISTS: u32 = 0;
    pub const RECEIVE_MESSAGE: u32 = 1;
    pub const SEND_MESSAGE: u32 = 2;
    pub const MAX_DATA_OBJECT_SIZE: u32 = 3;
}

/// Upcalls
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
