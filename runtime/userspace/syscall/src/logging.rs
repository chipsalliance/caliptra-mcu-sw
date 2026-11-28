// Licensed under the Apache-2.0 license

use crate::DefaultSyscalls;
use caliptra_mcu_libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use caliptra_mcu_libtockasync::TockSubscribe;
use core::cell::{Cell, RefCell};
use core::marker::PhantomData;
use embassy_sync::blocking_mutex::{raw::CriticalSectionRawMutex, Mutex};
use smallvec::SmallVec;

/// Upper bound on `yield_wait` calls [`LoggingSyscall::append_entry_sync`] makes
/// before giving up, so a capsule delivering unrelated upcalls can't spin it
/// forever in the panic/shutdown path.
const MAX_APPEND_SYNC_YIELDS: u32 = 64;

type LoggingSlots = SmallVec<[(u32, u32); 4]>;

// Inline slots leave small app heaps available for subscription futures.
static LOGGING_SLOTS: Mutex<CriticalSectionRawMutex, RefCell<LoggingSlots>> =
    Mutex::new(RefCell::new(LoggingSlots::new_const()));

struct LoggingSlot<S: Syscalls> {
    driver_num: u32,
    upcall: u32,
    _syscalls: PhantomData<S>,
}

impl<S: Syscalls> LoggingSlot<S> {
    fn acquire(driver_num: u32, upcall: u32) -> Result<Self, ErrorCode> {
        LOGGING_SLOTS.lock(|slots| {
            let mut slots = slots.borrow_mut();
            if slots.contains(&(driver_num, upcall)) {
                return Err(ErrorCode::Busy);
            }
            slots.try_reserve(1).map_err(|_| ErrorCode::NoMem)?;
            slots.push((driver_num, upcall));
            Ok(())
        })?;
        Ok(Self {
            driver_num,
            upcall,
            _syscalls: PhantomData,
        })
    }
}

impl<S: Syscalls> Drop for LoggingSlot<S> {
    fn drop(&mut self) {
        S::unsubscribe(self.driver_num, self.upcall);
        match self.upcall {
            subscribe::APPEND_DONE => S::unallow_ro(self.driver_num, ro_allow::APPEND),
            subscribe::READ_DONE => S::unallow_rw(self.driver_num, rw_allow::READ),
            _ => {}
        }
        // Keep ownership until both the subscription and allowed buffer are released.
        LOGGING_SLOTS.lock(|slots| {
            slots
                .borrow_mut()
                .retain(|slot| *slot != (self.driver_num, self.upcall));
        });
    }
}

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
///
/// Calls sharing a driver and completion upcall return `Busy` while another
/// caller owns that slot, including the interval between its upcall and cleanup.
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
        let _slot = LoggingSlot::<S>::acquire(self.driver_num, subscribe::APPEND_DONE)?;
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
                sub.cancel();
                Err(e)?;
            }
            Ok(TockSubscribe::subscribe_finish(sub))
        })?
        .await;
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

        {
            let _registration = AppendRegistration::<S>::new(self.driver_num, entry, &listener)?;
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
        }

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
        let _slot = LoggingSlot::<S>::acquire(self.driver_num, subscribe::READ_DONE)?;
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
                sub.cancel();
                Err(e)?;
            }
            Ok(TockSubscribe::subscribe_finish(sub))
        })?
        .await;
        result.and_then(|(len, err, _)| upcall_err_to_result(err).map(|_| len as usize))
    }

    /// Synchronizes the log to ensure all data is written to persistent storage.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn sync(&self) -> Result<(), ErrorCode> {
        self.command_with_completion(logging_cmd::SYNC, subscribe::SYNC_DONE)
            .await
    }

    /// Clears (erases) the log asynchronously.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn clear(&self) -> Result<(), ErrorCode> {
        self.command_with_completion(logging_cmd::ERASE, subscribe::ERASE_DONE)
            .await
    }

    /// Seeks to the beginning of the log asynchronously. Used by the logging system to reset the read position.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(ErrorCode)` - An error code if the operation fails.
    pub async fn seek_beginning(&self) -> Result<(), ErrorCode> {
        self.command_with_completion(logging_cmd::SEEK, subscribe::SEEK_DONE)
            .await
    }

    async fn command_with_completion(&self, command: u32, upcall: u32) -> Result<(), ErrorCode> {
        let _slot = LoggingSlot::<S>::acquire(self.driver_num, upcall)?;
        let mut sub = TockSubscribe::subscribe::<S>(self.driver_num, upcall);
        if let Err(error) = S::command(self.driver_num, command, 0, 0).to_result::<(), ErrorCode>()
        {
            sub.cancel();
            return Err(error);
        }
        let result = sub.as_mut().await;
        result.and_then(|(error, _, _)| upcall_err_to_result(error))
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

struct AppendRegistration<'a, S: Syscalls> {
    _slot: LoggingSlot<S>,
    _entry: &'a [u8],
    _listener: &'a AppendDoneListener<'a>,
}

impl<'a, S: Syscalls> AppendRegistration<'a, S> {
    fn new(
        driver_num: u32,
        entry: &'a [u8],
        listener: &'a AppendDoneListener<'a>,
    ) -> Result<Self, ErrorCode> {
        use caliptra_mcu_libtock_platform::{allow_ro, return_variant, syscall_class};
        // The guard retains both borrows and unregisters before either can expire.
        let registration = Self {
            _slot: LoggingSlot::acquire(driver_num, subscribe::APPEND_DONE)?,
            _entry: entry,
            _listener: listener,
        };
        let [variant, error, previous_len, _] = unsafe {
            S::syscall4::<{ syscall_class::ALLOW_RO }>([
                driver_num.into(),
                ro_allow::APPEND.into(),
                entry.as_ptr().into(),
                entry.len().into(),
            ])
        };
        if variant.as_u32() != u32::from(return_variant::SUCCESS_2_U32) {
            return Err(ErrorCode::try_from(error.as_u32()).unwrap_or(ErrorCode::Fail));
        }
        if usize::from(error) != 0 || usize::from(previous_len) != 0 {
            <DefaultConfig as allow_ro::Config>::returned_nonzero_buffer(
                driver_num,
                ro_allow::APPEND,
            );
        }
        let [variant, error, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe::APPEND_DONE.into(),
                (append_done as *const ()).into(),
                (listener as *const AppendDoneListener<'_>).into(),
            ])
        };
        if variant.as_u32() != u32::from(return_variant::SUCCESS_2_U32) {
            return Err(ErrorCode::try_from(error.as_u32()).unwrap_or(ErrorCode::Fail));
        }
        Ok(registration)
    }
}

extern "C" fn append_done(
    _length: u32,
    _lost: u32,
    error: u32,
    data: *const AppendDoneListener<'_>,
) {
    // Installed only by AppendRegistration, which bounds this pointer's lifetime.
    let listener = unsafe { &*data };
    listener.1.set(error);
    listener.0.set(true);
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

#[cfg(test)]
#[path = "logging_tests.rs"]
mod tests;
