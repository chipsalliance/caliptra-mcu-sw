// Licensed under the Apache-2.0 license

//! This provides the mailbox capsule that calls the underlying mailbox driver to
//! communicate with Caliptra.

use core::cell::Cell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::hil::time::{Alarm, AlarmClient};
use kernel::processbuffer::{
    ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer, WriteableProcessSlice,
};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{debug, ErrorCode, ProcessId};
use romtime::CaliptraSoC;

/// The driver number for Caliptra mailbox commands.
pub const DRIVER_NUM: usize = 0x8000_0009;

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

pub struct Mailbox<'a, A: Alarm<'a>> {
    pub alarm: &'a A,
    // The underlying Caliptra API SoC interface
    driver: TakeCell<'static, CaliptraSoC>,
    // Per-app state.
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    // Which app is currently using the storage.
    current_app: OptionalCell<ProcessId>,
    resp_min_size: Cell<usize>,
    resp_size: Cell<usize>,
}

impl<'a, A: Alarm<'a>> Mailbox<'a, A> {
    pub fn new(
        alarm: &'a A,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        driver: &'static mut CaliptraSoC,
    ) -> Mailbox<'a, A> {
        Mailbox {
            alarm,
            driver: TakeCell::new(driver),
            apps: grant,
            current_app: OptionalCell::empty(),
            resp_min_size: Cell::new(0),
            resp_size: Cell::new(0),
        }
    }

    // Check if any command is pending. If not, this command is executed.
    // If so, this command is queued and will be run when the pending
    // command is completed.
    fn enqueue_command(&self, command: u32, processid: ProcessId) -> Result<(), ErrorCode> {
        // Check if we're already executing a mailbox command.
        if self.current_app.is_some() {
            return Err(ErrorCode::BUSY);
        }
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
                                .map(|driver| {
                                    self.start_request(processid, driver, command, app_buffer)
                                })
                                .ok_or(ErrorCode::RESERVE)?
                        })
                        .map_err(|err| {
                            debug!("Error getting application buffer: {:?}", err);
                            ErrorCode::FAIL
                        })?
                })
        })?
    }

    fn start_request(
        &self,
        processid: ProcessId,
        driver: &mut CaliptraSoC,
        command: u32,
        app_buffer: &ReadableProcessSlice,
    ) -> Result<(), ErrorCode> {
        self.current_app.set(processid);
        self.resp_size.set(app_buffer.len());
        self.resp_min_size.set(app_buffer.len());

        match driver.start_mailbox_req(
            command,
            app_buffer.len(),
            app_buffer.chunks(4).map(|chunk| {
                let mut dest = [0u8; 4];
                chunk.copy_to_slice(&mut dest);
                u32::from_le_bytes(dest)
            }),
        ) {
            Ok(_) => {
                self.schedule_alarm();
                Ok(())
            }
            Err(err) => {
                debug!("Error starting mailbox command: {:?}", err);
                Err(ErrorCode::FAIL)
            }
        }
    }

    /// Returns true if the response was copied to the app.
    fn copy_from_mailbox(&self, driver: &mut CaliptraSoC, output: &WriteableProcessSlice) -> bool {
        match driver.finish_mailbox_resp(self.resp_min_size.get(), self.resp_size.get()) {
            Ok(resp_option) => {
                if let Some(mut resp) = resp_option {
                    for (i, word) in (&mut resp).enumerate() {
                        if let Some(out) = output.get(i * 4..((i + 1) * 4)) {
                            out.copy_from_slice(&word.to_le_bytes());
                        }
                    }
                    resp.verify_checksum()
                } else {
                    // no response, so we don't need to copy anything
                    true
                }
            }
            Err(err) => {
                debug!("Error copying from mailbox: {:?}", err);
                false
            }
        }
    }

    /// Returns true if the request was completed and the response was copied to the app.
    fn try_complete_request(&self, driver: &mut CaliptraSoC) -> bool {
        // response is ready, do the dance to pass it to the app
        if let Some(process_id) = self.current_app.take() {
            self.apps
                .enter(process_id, |_app, kernel_data| {
                    if let Ok(rw_buffer) =
                        kernel_data.get_readwrite_processbuffer(rw_allow::RESPONSE)
                    {
                        let result = rw_buffer
                            .mut_enter(|app_buffer| self.copy_from_mailbox(driver, app_buffer))
                            .map_err(|err| {
                                debug!("Error accessing writable buffer {:?}", err);
                                ErrorCode::FAIL
                            });

                        kernel_data
                            .schedule_upcall(
                                upcall::COMMAND_DONE,
                                (kernel::errorcode::into_statuscode(result.map(|_| ())), 0, 0),
                            )
                            .is_ok()
                            && result.unwrap_or_default()
                    } else {
                        false
                    }
                })
                .unwrap_or_default()
        } else {
            false
        }
    }

    fn schedule_alarm(&self) {
        let now = self.alarm.now();
        let dt = A::Ticks::from(10000);
        self.alarm.set_alarm(now, dt);
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for Mailbox<'a, A> {
    fn alarm(&self) {
        let reschedule = self
            .driver
            .map(|driver| {
                if driver.is_mailbox_busy() {
                    true
                } else {
                    !self.try_complete_request(driver)
                }
            })
            .unwrap_or_default();

        if reschedule {
            self.schedule_alarm();
        } else {
            let _ = self.alarm.disarm();
            self.current_app.take(); // clear the current app so another app can use the mailbox
        }
    }
}

/// Provide an interface for userland.
impl<'a, A: Alarm<'a>> SyscallDriver for Mailbox<'a, A> {
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
        _r3: usize,
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

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
