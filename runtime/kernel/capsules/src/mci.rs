// Licensed under the Apache-2.0 license

//! This provides the mailbox capsule that calls the underlying mailbox driver to
//! communicate with Caliptra.

use caliptra_api::CaliptraApiError;
use core::cell::Cell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::hil::time::{Alarm, AlarmClient};
use kernel::processbuffer::{
    ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer, WriteableProcessSlice,
};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{debug, ErrorCode, ProcessId};

/// The driver number for Caliptra mailbox commands.
pub const DRIVER_NUM: usize = 0xB000_0000;

/// IDs for subscribed upcalls.
mod upcall {
    /// Command done callback.
    pub const COMMAND_DONE: usize = 0;
    pub const COUNT: u8 = 1;
}

/// Ids for read-only allow buffers
mod ro_allow {
    /// Setup a buffer to read the mailbox request from.
    pub const REQUEST: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

/// Ids for read-write allow buffers
mod rw_allow {
    /// Setup a buffer to read the mailbox response into.
    pub const RESPONSE: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

#[derive(Default)]
pub struct App {}

pub struct Mci {
    driver: TakeCell<'static, romtime::Mci>,
    // Per-app state.
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    resp_min_size: Cell<usize>,
    resp_size: Cell<usize>,
}

impl Mci {
    pub fn new(
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        driver: &'static mut romtime::Mci,
    ) -> Mci {
        Mci {
            driver: TakeCell::new(driver),
            apps: grant,
            resp_min_size: Cell::new(0),
            resp_size: Cell::new(0),
        }
    }

    fn write_reg(&self, processid: ProcessId) -> Result<(), ErrorCode> {
        self.apps.enter(processid, |_app, kernel_data| {
            // copy the request so we can write async
            kernel_data
                .get_readonly_processbuffer(ro_allow::REQUEST)
                .map_err(|err| {
                    debug!("Error getting process buffer: {:?}", err);
                    ErrorCode::FAIL
                })
                .and_then(|ro_buffer| {
                    ro_buffer
                        .enter(|app_buffer| {
                            self.driver
                                .map(|driver| self.driver_write_reg(driver, app_buffer))
                                .ok_or(ErrorCode::RESERVE)?
                        })
                        .map_err(|err| {
                            debug!("Error getting application buffer: {:?}", err);
                            ErrorCode::FAIL
                        })?
                })?;
            kernel_data
                .schedule_upcall(upcall::COMMAND_DONE, (0, 0, 0))
                .map_err(|err| {
                    debug!("Error scheduling upcall: {:?}", err);
                    ErrorCode::FAIL
                })
        })?
    }

    fn driver_write_reg(
        &self,
        driver: &mut romtime::Mci,
        app_buffer: &ReadableProcessSlice,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    fn read_reg(&self) -> Result<(), ErrorCode> {
        Ok(())
    }



}


/// Provide an interface for userland.
impl SyscallDriver for Mci {
    /// Command interface.
    ///
    /// Commands are selected by the lowest 8 bits of the first argument.
    ///
    /// ### `command_num`
    ///
    /// - `0`: Return Ok(()) if this driver is included on the platform.
    /// - `1`: Enqueue a mailbox command
    fn command(
        &self,
        syscall_command_num: usize,
        command: usize,
        payload_size: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match syscall_command_num {
            0 => CommandReturn::success(),

            1 => {
                // Enqueue a mailbox command
                let res = self.write_reg( processid);

                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            2 => {
                // Initiate a mailbox command
                let res = self.write_reg( processid);
                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
