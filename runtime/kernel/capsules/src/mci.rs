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
        for chunk in app_buffer.chunks(4) {
            if chunk.len() == 4 {
                let mut buf = [0u8; 4];
                chunk.copy_to_slice(&mut buf);
                let data = u32::from_le_bytes(buf);
                driver.write_data(data).map_err(|_| ErrorCode::FAIL)?;
            } else {
                // If the last chunk is not 4 bytes, we can't write it to the mailbox
                debug!("Error: Incomplete data chunk in mailbox request");
                return Err(ErrorCode::FAIL);
            }
        }
        Ok(())
    }

    fn read_reg(&self) -> Result<(), ErrorCode> {
        // Check if we're already executing a mailbox command.
        if self.current_app.is_none() {
            return Err(ErrorCode::CANCEL);
        }
        self.driver
            .map(|driver| match driver.execute_command() {
                Ok(()) => {
                    self.schedule_alarm();
                    Ok(())
                }
                Err(_) => Err(ErrorCode::FAIL),
            })
            .unwrap_or(Err(ErrorCode::FAIL))
    }

    /// Returns number of bytes in response  if the response was copied to the app.
    fn copy_from_mailbox(
        &self,
        driver: &mut CaliptraSoC,
        output: &WriteableProcessSlice,
    ) -> Result<usize, CaliptraApiError> {
        match driver.finish_mailbox_resp(self.resp_min_size.get(), self.resp_size.get()) {
            Ok(resp_option) => {
                if let Some(mut resp) = resp_option {
                    for (i, word) in (&mut resp).enumerate() {
                        if let Some(out) = output.get(i * 4..((i + 1) * 4)) {
                            out.copy_from_slice(&word.to_le_bytes());
                        }
                    }
                    resp.verify_checksum().map(|_| resp.len())
                } else {
                    // no response, so we don't need to copy anything
                    Ok(0)
                }
            }
            Err(err) => {
                debug!("Error copying from mailbox: {:?}", err);
                Err(err)
            }
        }
    }

    /// Completes the request by copying the response or error from the mailbox.
    fn try_complete_request(&self, driver: &mut CaliptraSoC) {
        // response is ready, do the dance to pass it to the app
        if let Some(process_id) = self.current_app.take() {
            let enter_result = self.apps.enter(process_id, |_app, kernel_data| {
                if let Ok(rw_buffer) = kernel_data.get_readwrite_processbuffer(rw_allow::RESPONSE) {
                    match rw_buffer.mut_enter(|app_buffer| {
                        self.resp_size.set(app_buffer.len());
                        self.resp_min_size.set(app_buffer.len());
                        self.copy_from_mailbox(driver, app_buffer)
                    }) {
                        Err(err) => {
                            debug!("Error accessing writable buffer {:?}", err);
                        }
                        Ok(Err(err)) => {
                            // Error from Caliptra
                            let err = match err {
                                CaliptraApiError::MciCmdFailed(err) => err,
                                CaliptraApiError::MciRespInvalidChecksum { .. } => 0xffff_ffff,
                                _ => 0xffff_fffe,
                            };
                            if let Err(err) = kernel_data
                                .schedule_upcall(upcall::COMMAND_DONE, (0, err as usize, 0))
                            {
                                debug!("Error scheduling upcall: {:?}", err);
                            }
                        }
                        Ok(Ok(len)) => {
                            if let Err(err) =
                                kernel_data.schedule_upcall(upcall::COMMAND_DONE, (len, 0, 0))
                            {
                                debug!("Error scheduling upcall: {:?}", err);
                            }
                        }
                    }
                }
            });
            if let Err(err) = enter_result {
                debug!("Error entering app: {:?}", err);
            }
        }
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
                let res = self.enqueue_command(command as u32, processid);

                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            2 => {
                // Initiate a mailbox command
                let res = self.initiate_request(command as u32, payload_size, processid);
                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            3 => {
                // Send next chunk
                let res = self.send_next_chunk(processid);
                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            4 => {
                // Execute the command
                let res = self.execute();
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
