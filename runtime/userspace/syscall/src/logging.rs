// Licensed under the Apache-2.0 license

use crate::DefaultSyscalls;
use core::marker::PhantomData;
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

pub struct LoggingSyscall<S: Syscalls = DefaultSyscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Default for LoggingSyscall<S> {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents an asynchronous logging interface.
impl<S: Syscalls> LoggingSyscall<S> {
    /// Creates a new LoggingSyscall instance with the default driver number.
    ///
    /// # Returns
    /// A new `LoggingSyscall` instance.
    pub fn new() -> Self {
        Self {
            syscall: PhantomData,
            driver_num: driver_num::LOGGING_FLASH,
        }
    }

    /// Checks if the logging driver exists.
    ///
    /// # Returns
    /// - `Ok(())` - If the driver exists.
    /// - `Err(ErrorCode)` - An error code if the operation fails.
    pub fn exists(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, logging_cmd::EXISTS, 0, 0).to_result()
    }
    /// Gets the capacity of the logging storage.
    ///
    /// # Returns
    /// - `Ok(capacity)` - The capacity in bytes.
    /// - `Err(ErrorCode)` - An error code if the operation fails.
    pub fn get_capacity(&self) -> Result<usize, ErrorCode> {
        S::command(self.driver_num, logging_cmd::GET_CAP, 0, 0)
            .to_result()
            .map(|x: u32| x as usize)
    }

    /// Appends an entry to the log asynchronously.
    ///
    /// # Arguments
    /// - `entry`: The data to append.
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn append_entry(&self, entry: &[u8]) -> Result<(), ErrorCode> {
        let result = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                subscribe::APPEND_DONE,
                ro_allow::APPEND,
                entry,
            );
            if let Err(e) = S::command(self.driver_num, logging_cmd::APPEND, entry.len() as u32, 0)
                .to_result::<(), ErrorCode>()
            {
                S::unallow_ro(self.driver_num, ro_allow::APPEND);
                sub.cancel();
                Err(e)?;
            }
            Ok(TockSubscribe::subscribe_finish(sub))
        })?
        .await;
        S::unallow_ro(self.driver_num, ro_allow::APPEND);
        result.map(|_| ())
    }
    /// Reads an entry from the log asynchronously into the provided buffer.
    ///
    /// # Arguments
    /// * `buffer` - The mutable buffer to read log data into.
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of bytes read.
    /// * `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn read_entry(&self, buffer: &mut [u8]) -> Result<usize, ErrorCode> {
        let result = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                subscribe::READ_DONE,
                rw_allow::READ,
                buffer,
            );
            if let Err(e) = S::command(self.driver_num, logging_cmd::READ, buffer.len() as u32, 0)
                .to_result::<(), ErrorCode>()
            {
                S::unallow_rw(self.driver_num, rw_allow::READ);
                sub.cancel();
                Err(e)?;
            }
            Ok(TockSubscribe::subscribe_finish(sub))
        })?
        .await;
        S::unallow_rw(self.driver_num, rw_allow::READ);
        result.map(|(len, _, _)| len as usize)
    }

    /// Synchronizes the log to ensure all data is written to persistent storage.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn sync(&self) -> Result<(), ErrorCode> {
        let sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::SYNC_DONE);
        S::command(self.driver_num, logging_cmd::SYNC, 0, 0).to_result::<(), ErrorCode>()?;
        sub.await.map(|_| Ok(()))?
    }

    /// Clears (erases) the log asynchronously.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn clear(&self) -> Result<(), ErrorCode> {
        let sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::ERASE_DONE);
        S::command(self.driver_num, logging_cmd::ERASE, 0, 0).to_result::<(), ErrorCode>()?;
        sub.await.map(|_| Ok(()))?
    }

    /// Seeks to the beginning of the log asynchronously. Used by the logging system to reset the read position.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn seek_beginning(&self) -> Result<(), ErrorCode> {
        let sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::SEEK_DONE);
        S::command(self.driver_num, logging_cmd::SEEK, 0, 0).to_result::<(), ErrorCode>()?;
        sub.await.map(|_| Ok(()))?
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

pub mod driver_num {
    pub const LOGGING_FLASH: u32 = 0x9001_0000;
}

// Upcalls
mod subscribe {
    /// Read done callback.
    pub const READ_DONE: u32 = 0;
    /// Seek done callback.
    pub const SEEK_DONE: u32 = 1;
    /// Append done callback.
    pub const APPEND_DONE: u32 = 2;
    /// Sync done callback.
    pub const SYNC_DONE: u32 = 3;
    /// Erase done callback
    pub const ERASE_DONE: u32 = 4;
}

mod ro_allow {
    /// Write buffer for the entry to be appended to the log.
    pub const APPEND: u32 = 0;
}

mod rw_allow {
    /// Read buffer for the entry to be read from the log.
    pub const READ: u32 = 0;
}

/// Command IDs for logging driver capsule
///
/// - `0`: Return Ok(()) if this driver is included on the platform.
/// - `1`: Read an entry from the log.
/// - `2`: Append an entry to the log.
/// - `3`: Seek to the beginning of the log.
/// - `4`: Synchronize the log.
/// - `5`: Clear the log.
/// - `6`: Get the capacity of the logging storage.
mod logging_cmd {
    pub const EXISTS: u32 = 0;
    pub const READ: u32 = 1;
    pub const APPEND: u32 = 2;
    pub const SEEK: u32 = 3;
    pub const SYNC: u32 = 4;
    pub const ERASE: u32 = 5;
    pub const GET_CAP: u32 = 6;
}
