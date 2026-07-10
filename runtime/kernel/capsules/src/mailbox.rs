// Licensed under the Apache-2.0 license

//! This provides the mailbox capsule that calls the underlying mailbox driver to
//! communicate with Caliptra.

use caliptra_api::CaliptraApiError;
use caliptra_mcu_romtime::println;
use caliptra_mcu_romtime::CaliptraSoC;
use core::cell::Cell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::hil::time::{Alarm, AlarmClient};
use kernel::processbuffer::{
    ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer, WriteableProcessSlice,
};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{ErrorCode, ProcessId};

fn log_caliptra_error(err: &CaliptraApiError) {
    match err {
        CaliptraApiError::MailboxCmdFailed(code) => {
            capsule_error!("MBOX", "Mailbox cmd failed: 0x{:08x}", code)
        }
        CaliptraApiError::UnknownCommandStatus(code) => {
            capsule_error!("MBOX", "Unknown command status: 0x{:08x}", code)
        }
        CaliptraApiError::MailboxRespInvalidChecksum { expected, actual } => capsule_error!(
            "MBOX",
            "Invalid checksum: exp=0x{:08x} act=0x{:08x}",
            expected,
            actual
        ),
        CaliptraApiError::MailboxRespInvalidFipsStatus(status) => {
            capsule_error!("MBOX", "Invalid FIPS status: 0x{:08x}", status)
        }
        CaliptraApiError::MailboxUnexpectedResponseLen {
            expected_min,
            expected_max,
            actual,
        } => capsule_error!(
            "MBOX",
            "Unexpected resp len: min={} max={} actual={}",
            expected_min,
            expected_max,
            actual
        ),
        CaliptraApiError::UnexpectedMailboxFsmStatus { expected, actual } => capsule_error!(
            "MBOX",
            "Unexpected FSM status: exp=0x{:08x} act=0x{:08x}",
            expected,
            actual
        ),
        CaliptraApiError::BufferTooLargeForMailbox => {
            capsule_error!("MBOX", "Buffer too large for mailbox")
        }
        CaliptraApiError::UnableToLockMailbox => capsule_error!("MBOX", "Unable to lock mailbox"),
        CaliptraApiError::MailboxTimeout => capsule_error!("MBOX", "Mailbox timeout"),
        CaliptraApiError::MailboxRespTypeTooSmall => {
            capsule_error!("MBOX", "Response type too small")
        }
        CaliptraApiError::MailboxReqTypeTooSmall => {
            capsule_error!("MBOX", "Request type too small")
        }
        CaliptraApiError::MailboxNoResponseData => capsule_error!("MBOX", "No response data"),
        _ => capsule_error!("MBOX", "Mailbox error"),
    }
}

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

/// State machine for the chunked mailbox command flow (commands 2/3/4).
#[derive(Clone, Copy, PartialEq)]
enum MailboxState {
    /// No mailbox operation in progress.
    Idle,
    /// After initiate_request (command 2), waiting for data chunks and execute.
    Initiated,
    /// After execute (command 4) or enqueue_command (command 1), polling for response.
    Executing,
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
    // Current state of the mailbox state machine.
    state: Cell<MailboxState>,
    // Timeout ticks for the initiated state before auto-resetting to idle.
    // If None, no timeout is enforced.
    timeout_ticks: Option<u32>,
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
        timeout_ticks: Option<u32>,
    ) -> Mailbox<'a, A> {
        Mailbox {
            alarm,
            driver: TakeCell::new(driver),
            apps: grant,
            current_app: OptionalCell::empty(),
            state: Cell::new(MailboxState::Idle),
            timeout_ticks,
            resp_min_size: Cell::new(0),
            resp_size: Cell::new(0),
        }
    }

    // Check if any command is pending. If not, this command is executed.
    // If so, this command is queued and will be run when the pending
    // command is completed.
    fn enqueue_command(&self, command: u32, processid: ProcessId) -> Result<(), ErrorCode> {
        // Check if we're already executing a mailbox command.
        if self.state.get() != MailboxState::Idle {
            return Err(ErrorCode::BUSY);
        }
        self.apps.enter(processid, |_app, kernel_data| {
            // copy the request so we can write async
            kernel_data
                .get_readonly_processbuffer(ro_allow::REQUEST)
                .map_err(|err| {
                    capsule_error!("MBOX", "Error getting process buffer: 0x{:x}", err as u32);
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
                            capsule_error!(
                                "MBOX",
                                "Error getting application buffer: 0x{:08x}",
                                err as u32
                            );
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
        self.state.set(MailboxState::Executing);

        // App buffer contains the full payload. The mailbox is 32-bit wide and
        // payload length is delimited by `dlen` (= `app_buffer.len()`), so the
        // final partial word (if any) must be zero-padded into a u32 rather
        // than rejected or truncated.
        match driver.start_mailbox_req(
            command,
            app_buffer.len(),
            app_buffer.chunks(4).map(|chunk| {
                let mut dest = [0u8; 4];
                let n = chunk.len();
                chunk.copy_to_slice(&mut dest[..n]);
                u32::from_le_bytes(dest)
            }),
        ) {
            Ok(_) => {
                self.schedule_alarm();
                Ok(())
            }
            Err(err) => {
                log_caliptra_error(&err);
                self.state.set(MailboxState::Idle);
                self.current_app.take();
                Err(ErrorCode::FAIL)
            }
        }
    }

    fn initiate_request(
        &self,
        command: u32,
        payload_size: usize,
        processid: ProcessId,
    ) -> Result<(), ErrorCode> {
        // Check if we're already executing a mailbox command.
        if self.state.get() != MailboxState::Idle {
            return Err(ErrorCode::BUSY);
        }
        self.current_app.set(processid);
        self.state.set(MailboxState::Initiated);
        self.driver
            .map(
                |driver| match driver.initiate_request(command, payload_size) {
                    Ok(()) => {
                        self.schedule_initiate_timeout();
                        Ok(())
                    }
                    Err(_) => {
                        self.state.set(MailboxState::Idle);
                        self.current_app.take();
                        Err(ErrorCode::FAIL)
                    }
                },
            )
            .ok_or(ErrorCode::RESERVE)?
    }

    fn send_next_chunk(&self, processid: ProcessId) -> Result<(), ErrorCode> {
        // Only allowed after initiate_request (command 2).
        if self.state.get() != MailboxState::Initiated {
            return Err(ErrorCode::INVAL);
        }
        // Verify that the caller is the app that initiated the request.
        if self.current_app.get() != Some(processid) {
            return Err(ErrorCode::INVAL);
        }
        self.apps.enter(processid, |_app, kernel_data| {
            // copy the request so we can write async
            kernel_data
                .get_readonly_processbuffer(ro_allow::REQUEST)
                .map_err(|err| {
                    capsule_error!("MBOX", "Error getting process buffer: 0x{:x}", err as u32);
                    ErrorCode::FAIL
                })
                .and_then(|ro_buffer| {
                    ro_buffer
                        .enter(|app_buffer| {
                            self.driver
                                .map(|driver| self.write_chunk(driver, app_buffer))
                                .ok_or(ErrorCode::RESERVE)?
                        })
                        .map_err(|err| {
                            capsule_error!(
                                "MBOX",
                                "Error getting application buffer: 0x{:08x}",
                                err as u32
                            );
                            ErrorCode::FAIL
                        })?
                })?;
            // Reset the timeout since the user is actively sending data.
            self.schedule_initiate_timeout();
            kernel_data
                .schedule_upcall(upcall::COMMAND_DONE, (0, 0, 0))
                .map_err(|err| {
                    capsule_error!("MBOX", "Error scheduling upcall: 0x{:x}", err as u32);
                    ErrorCode::FAIL
                })
        })?
    }

    fn write_chunk(
        &self,
        driver: &mut CaliptraSoC,
        app_buffer: &ReadableProcessSlice,
    ) -> Result<(), ErrorCode> {
        // The mailbox FIFO is 32-bit wide and the payload length is delimited
        // by `dlen`, so a trailing partial word is zero-padded into a u32
        // (matching the policy in `start_request`).
        for chunk in app_buffer.chunks(4) {
            let mut buf = [0u8; 4];
            let n = chunk.len();
            chunk.copy_to_slice(&mut buf[..n]);
            let data = u32::from_le_bytes(buf);
            driver.write_data(data).map_err(|_| ErrorCode::FAIL)?;
        }
        Ok(())
    }

    fn abort_initiated_request(&self, processid: ProcessId) -> Result<(), ErrorCode> {
        // Only allowed after initiate_request (command 2).
        if self.state.get() != MailboxState::Initiated {
            return Err(ErrorCode::INVAL);
        }
        // Verify that the caller is the app that initiated the request.
        if self.current_app.get() != Some(processid) {
            return Err(ErrorCode::INVAL);
        }
        self.driver
            .map(|driver| driver.abort_request())
            .ok_or(ErrorCode::FAIL)?;
        let _ = self.alarm.disarm();
        self.state.set(MailboxState::Idle);
        self.current_app.take();
        Ok(())
    }

    fn execute(&self, processid: ProcessId) -> Result<(), ErrorCode> {
        // Only allowed after initiate_request (command 2).
        if self.state.get() != MailboxState::Initiated {
            return Err(ErrorCode::INVAL);
        }
        // Verify that the caller is the app that initiated the request.
        if self.current_app.get() != Some(processid) {
            return Err(ErrorCode::INVAL);
        }
        self.state.set(MailboxState::Executing);
        self.driver
            .map(|driver| match driver.execute_command() {
                Ok(()) => {
                    self.schedule_alarm();
                    Ok(())
                }
                Err(_err) => {
                    self.state.set(MailboxState::Idle);
                    self.current_app.take();
                    Err(ErrorCode::FAIL)
                }
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
                log_caliptra_error(&err);
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
                            capsule_error!(
                                "MBOX",
                                "Error accessing writable buffer: 0x{:08x}",
                                err as u32
                            );
                        }
                        Ok(Err(err)) => {
                            // Error from Caliptra
                            let err = match err {
                                CaliptraApiError::MailboxCmdFailed(err) => err,
                                CaliptraApiError::MailboxRespInvalidChecksum { .. } => 0xffff_ffff,
                                _ => 0xffff_fffe,
                            };
                            if let Err(err) = kernel_data
                                .schedule_upcall(upcall::COMMAND_DONE, (0, err as usize, 0))
                            {
                                capsule_error!(
                                    "MBOX",
                                    "Error scheduling upcall: 0x{:08x}",
                                    err as u32
                                );
                            }
                        }
                        Ok(Ok(len)) => {
                            if let Err(err) =
                                kernel_data.schedule_upcall(upcall::COMMAND_DONE, (len, 0, 0))
                            {
                                capsule_error!(
                                    "MBOX",
                                    "Error scheduling upcall: 0x{:08x}",
                                    err as u32
                                );
                            }
                        }
                    }
                }
            });
            if let Err(err) = enter_result {
                capsule_error!("MBOX", "Error entering app: 0x{:x}", err as u32);
            }
        }
    }

    fn schedule_alarm(&self) {
        let now = self.alarm.now();
        let dt = A::Ticks::from(10000);
        self.alarm.set_alarm(now, dt);
    }

    fn schedule_initiate_timeout(&self) {
        if let Some(ticks) = self.timeout_ticks {
            let now = self.alarm.now();
            let dt = A::Ticks::from(ticks);
            self.alarm.set_alarm(now, dt);
        }
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for Mailbox<'a, A> {
    fn alarm(&self) {
        match self.state.get() {
            MailboxState::Initiated => {
                // Timeout: user didn't complete the chunked send in time.
                capsule_debug!("MBOX", "Mailbox initiate timeout: resetting to idle");
                let _ = self.alarm.disarm();
                // Release the HW mailbox lock by clearing the execute bit.
                self.driver.map(|driver| {
                    driver.abort_request();
                });
                self.state.set(MailboxState::Idle);
                self.current_app.take();
            }
            MailboxState::Executing => {
                let reschedule = self
                    .driver
                    .map(|driver| {
                        if driver.is_mailbox_busy() {
                            true
                        } else {
                            self.try_complete_request(driver);
                            false
                        }
                    })
                    .unwrap_or_default();

                if reschedule {
                    self.schedule_alarm();
                } else {
                    let _ = self.alarm.disarm();
                    self.state.set(MailboxState::Idle);
                    self.current_app.take();
                }
            }
            MailboxState::Idle => {
                let _ = self.alarm.disarm();
            }
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
                let res = self.execute(processid);
                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            5 => {
                // Abort an initiated chunked command
                let res = self.abort_initiated_request(processid);
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
