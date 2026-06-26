// Licensed under the Apache-2.0 license

use crate::DefaultSyscalls;
use caliptra_mcu_libtock_platform::subscribe::OneId;
use caliptra_mcu_libtock_platform::{
    share, AllowRo, DefaultConfig, ErrorCode, Subscribe, Syscalls, Upcall,
};
use caliptra_mcu_libtockasync::TockSubscribe;
use core::cell::Cell;
use core::marker::PhantomData;

/// Upper bound on `yield_wait` calls [`LoggingSyscall::append_entry_sync`] makes
/// before giving up, so a capsule delivering unrelated upcalls can't spin it
/// forever in the panic/shutdown path.
const MAX_APPEND_SYNC_YIELDS: u32 = 64;

pub struct LoggingSyscall<S: Syscalls = DefaultSyscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Default for LoggingSyscall<S> {
    fn default() -> Self {
        Self::new(driver_num::LOGGING_FLASH)
    }
}

/// Represents an asynchronous logging interface.
impl<S: Syscalls> LoggingSyscall<S> {
    /// Creates a new LoggingSyscall instance with the given driver number.
    ///
    /// # Returns
    /// A new `LoggingSyscall` instance.
    pub fn new(driver_num: u32) -> Self {
        Self {
            syscall: PhantomData,
            driver_num,
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
        result.and_then(|(_len, _lost, err)| upcall_err_to_result(err).map(|_| ()))
    }

    /// Append an entry to the log synchronously, blocking until the kernel
    /// signals completion. For panic/shutdown contexts where `.await` is
    /// unavailable; spins on `yield_wait` until the append-done upcall fires.
    ///
    /// The wait is bounded: if `MAX_APPEND_SYNC_YIELDS` upcalls arrive without
    /// append-done, it gives up with `ErrorCode::Busy` rather than spin forever.
    /// A fully unresponsive capsule (no upcall at all) still blocks in
    /// `yield_wait` and relies on the platform watchdog.
    pub fn append_entry_sync(&self, entry: &[u8]) -> Result<(), ErrorCode> {
        let done = Cell::new(false);
        let err = Cell::new(0u32);
        let listener = AppendDoneListener(&done, &err);

        share::scope::<
            (
                AllowRo<S, { driver_num::LOGGING_FLASH }, { ro_allow::APPEND }>,
                Subscribe<S, { driver_num::LOGGING_FLASH }, { subscribe::APPEND_DONE }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_ro, subscribe) = handle.split();
            S::allow_ro::<DefaultConfig, { driver_num::LOGGING_FLASH }, { ro_allow::APPEND }>(
                allow_ro, entry,
            )?;
            S::subscribe::<
                _,
                _,
                DefaultConfig,
                { driver_num::LOGGING_FLASH },
                { subscribe::APPEND_DONE },
            >(subscribe, &listener)?;
            S::command(self.driver_num, logging_cmd::APPEND, entry.len() as u32, 0)
                .to_result::<(), ErrorCode>()?;
            let mut yields = 0;
            while !done.get() {
                if yields >= MAX_APPEND_SYNC_YIELDS {
                    return Err::<(), ErrorCode>(ErrorCode::Busy);
                }
                yields += 1;
                S::yield_wait();
            }
            Ok::<(), ErrorCode>(())
        })?;

        upcall_err_to_result(err.get())
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
        result.and_then(|(len, err, _)| upcall_err_to_result(err).map(|_| len as usize))
    }

    /// Synchronizes the log to ensure all data is written to persistent storage.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn sync(&self) -> Result<(), ErrorCode> {
        let sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::SYNC_DONE);
        S::command(self.driver_num, logging_cmd::SYNC, 0, 0).to_result::<(), ErrorCode>()?;
        let (err, _, _) = sub.await?;
        upcall_err_to_result(err)
    }

    /// Clears (erases) the log asynchronously.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn clear(&self) -> Result<(), ErrorCode> {
        let sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::ERASE_DONE);
        S::command(self.driver_num, logging_cmd::ERASE, 0, 0).to_result::<(), ErrorCode>()?;
        let (err, _, _) = sub.await?;
        upcall_err_to_result(err)
    }

    /// Seeks to the beginning of the log asynchronously. Used by the logging system to reset the read position.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn seek_beginning(&self) -> Result<(), ErrorCode> {
        let sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::SEEK_DONE);
        S::command(self.driver_num, logging_cmd::SEEK, 0, 0).to_result::<(), ErrorCode>()?;
        let (err, _, _) = sub.await?;
        upcall_err_to_result(err)
    }
}

fn upcall_err_to_result(err: u32) -> Result<(), ErrorCode> {
    if err == 0 {
        Ok(())
    } else {
        Err(ErrorCode::try_from(err).unwrap_or(ErrorCode::Fail))
    }
}

/// Captures the append-done upcall for [`LoggingSyscall::append_entry_sync`].
/// The append-done upcall arguments are `(length, records_lost, error)`.
struct AppendDoneListener<'a>(&'a Cell<bool>, &'a Cell<u32>);

impl Upcall<OneId<{ driver_num::LOGGING_FLASH }, { subscribe::APPEND_DONE }>>
    for AppendDoneListener<'_>
{
    fn upcall(&self, _len: u32, _records_lost: u32, error: u32) {
        self.1.set(error);
        self.0.set(true);
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

pub mod driver_num {
    /// Conventional driver number for instance 0; additional instances are platform-defined.
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
    /// Read-only buffer containing the entry to be appended to the log.
    pub const APPEND: u32 = 0;
}

mod rw_allow {
    /// Read-write buffer for receiving the entry to be read from the log.
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
