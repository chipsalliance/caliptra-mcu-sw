// Licensed under the Apache-2.0 license

//! Device-neutral ownership, queueing, and completion handling for logging syscalls.

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::hil::log::{LogRead, LogReadClient, LogWrite, LogWriteClient};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{ErrorCode, ProcessId};

pub const LOGGING_FLASH_DRIVER_NUM: usize = 0x9001_0000;
pub const BUF_LEN: usize = 256;

/// IDs for subscribed upcalls.
mod upcall {
    pub const READ_DONE: usize = 0;
    pub const SEEK_DONE: usize = 1;
    pub const APPEND_DONE: usize = 2;
    pub const SYNC_DONE: usize = 3;
    pub const ERASE_DONE: usize = 4;
    pub const COUNT: u8 = 5;
}

/// Ids for read-only allow buffers
mod ro_allow {
    pub const APPEND: usize = 0;
    pub const COUNT: u8 = 1;
}

/// Ids for read-write allow buffers
mod rw_allow {
    pub const READ: usize = 0;
    pub const COUNT: u8 = 1;
}

mod logging_cmd {
    pub const READ: usize = 1;
    pub const APPEND: usize = 2;
    pub const SEEK: usize = 3;
    pub const SYNC: usize = 4;
    pub const ERASE: usize = 5;
    pub const GET_CAP: usize = 6;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoggingOps {
    Idle,
    Read,
    Seek,
    Append,
    Sync,
    Erase,
}

pub struct App {
    pending_command: bool,
    command: LoggingOps,
    arg1: usize,
    _arg2: usize,
}

impl Default for App {
    fn default() -> App {
        App {
            pending_command: false,
            command: LoggingOps::Idle,
            arg1: 0,
            _arg2: 0,
        }
    }
}

pub trait LogReadWrite<'a>: LogRead<'a, EntryID = usize> + LogWrite<'a> {}
impl<'a, T: LogRead<'a, EntryID = usize> + LogWrite<'a>> LogReadWrite<'a> for T {}

struct LoggingDriver<'a> {
    driver: &'a dyn LogReadWrite<'a>,
    driver_num: usize,
    // Per-app state.
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    // Internal buffer for copying appslices into.
    buffer: TakeCell<'static, [u8]>,
    current_app: OptionalCell<ProcessId>,
}

impl<'a> LoggingDriver<'a> {
    fn new(
        driver: &'a dyn LogReadWrite<'a>,
        driver_num: usize,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        buffer: &'static mut [u8],
    ) -> Self {
        Self {
            driver,
            driver_num,
            apps: grant,
            buffer: TakeCell::new(buffer),
            current_app: OptionalCell::empty(),
        }
    }

    fn get_driver_num(&self) -> usize {
        self.driver_num
    }

    fn dispatch(
        &self,
        command: LoggingOps,
        processid: ProcessId,
        arg1: usize,
        arg2: usize,
    ) -> CommandReturn {
        match self.enqueue_command(command, Some(processid), arg1, arg2) {
            Ok(()) => CommandReturn::success(),
            Err(error) => CommandReturn::failure(error),
        }
    }

    fn capacity(&self) -> CommandReturn {
        CommandReturn::success_u32(self.driver.get_size() as u32)
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }

    fn enqueue_command(
        &self,
        command: LoggingOps,
        processid: Option<ProcessId>,
        arg1: usize,
        _arg2: usize,
    ) -> Result<(), ErrorCode> {
        processid.map_or(Err(ErrorCode::FAIL), |processid| {
            self.apps
                .enter(processid, |app, kernel_data| {
                    let (needs_buffer, allow_buf_len) = match command {
                        LoggingOps::Read => (
                            true,
                            kernel_data
                                .get_readwrite_processbuffer(rw_allow::READ)
                                .map_or(0, |read| read.len()),
                        ),
                        LoggingOps::Append => (
                            true,
                            kernel_data
                                .get_readonly_processbuffer(ro_allow::APPEND)
                                .map_or(0, |write| write.len()),
                        ),
                        _ => (false, 0),
                    };
                    if needs_buffer && (allow_buf_len == 0 || self.buffer.is_none()) {
                        return Err(ErrorCode::RESERVE);
                    }
                    if needs_buffer
                        && (arg1 > allow_buf_len
                            || (command == LoggingOps::Append
                                && self.buffer.map_or(true, |buffer| arg1 > buffer.len())))
                    {
                        return Err(ErrorCode::SIZE);
                    }

                    if self.current_app.is_none() {
                        self.current_app.set(processid);
                        if command == LoggingOps::Append {
                            let _ = kernel_data
                                .get_readonly_processbuffer(ro_allow::APPEND)
                                .and_then(|write| {
                                    write.enter(|app_buffer| {
                                        self.buffer.map(|kernel_buffer| {
                                            let write_len =
                                                arg1.min(app_buffer.len()).min(kernel_buffer.len());
                                            let d = &app_buffer[0..write_len];
                                            d.copy_to_slice(&mut kernel_buffer[0..write_len]);
                                        });
                                    })
                                });
                        }

                        match self.userspace_call_driver(command, arg1, _arg2) {
                            Ok(()) => Ok(()),
                            Err(e) => {
                                // If the driver call failed immediately, clear current_app
                                // so other apps can proceed.
                                self.current_app.clear();
                                Err(e)
                            }
                        }
                    } else if app.pending_command {
                        Err(ErrorCode::NOMEM)
                    } else {
                        app.pending_command = true;
                        app.command = command;
                        app.arg1 = arg1;
                        app._arg2 = _arg2;
                        Ok(())
                    }
                })
                .unwrap_or_else(|err| Err(err.into()))
        })
    }

    fn userspace_call_driver(
        &self,
        command: LoggingOps,
        arg1: usize,
        _arg2: usize,
    ) -> Result<(), ErrorCode> {
        match command {
            LoggingOps::Read | LoggingOps::Append => {
                // At this point, buffer is guaranteed to be available and pre-filled if needed
                let buffer = self.buffer.take().ok_or(ErrorCode::RESERVE)?;
                let len = arg1.min(buffer.len());
                let res = if command == LoggingOps::Read {
                    self.driver.read(buffer, len)
                } else {
                    self.driver.append(buffer, len)
                };
                match res {
                    Ok(()) => Ok(()),
                    Err((ecode, buf)) => {
                        self.buffer.replace(buf);
                        Err(ecode)
                    }
                }
            }
            LoggingOps::Seek => match arg1 {
                0 => self.driver.seek(self.driver.log_start()),
                1 => self.driver.seek(self.driver.log_end()),
                _ => Err(ErrorCode::INVAL),
            },
            LoggingOps::Sync => self.driver.sync(),
            LoggingOps::Erase => self.driver.erase(),
            _ => Err(ErrorCode::INVAL),
        }
    }

    fn check_queue(&self) {
        for cntr in self.apps.iter() {
            let processid = cntr.processid();
            let pending = cntr.enter(|app, _| {
                if app.pending_command {
                    app.pending_command = false;
                    Some((app.command, app.arg1, app._arg2))
                } else {
                    None
                }
            });

            if let Some((command, arg1, arg2)) = pending {
                match self.enqueue_command(command, Some(processid), arg1, arg2) {
                    Ok(()) => break,
                    Err(error) => {
                        let _ = self.apps.enter(processid, |_, kernel_data| {
                            let (upcall, args) = match command {
                                LoggingOps::Read => (upcall::READ_DONE, (0, error as usize, 0)),
                                LoggingOps::Append => (upcall::APPEND_DONE, (0, 0, error as usize)),
                                LoggingOps::Seek => (upcall::SEEK_DONE, (error as usize, 0, 0)),
                                LoggingOps::Sync => (upcall::SYNC_DONE, (error as usize, 0, 0)),
                                LoggingOps::Erase => (upcall::ERASE_DONE, (error as usize, 0, 0)),
                                LoggingOps::Idle => return,
                            };
                            kernel_data.schedule_upcall(upcall, args).ok();
                        });
                    }
                }
            }
        }
    }
}

impl LogReadClient for LoggingDriver<'_> {
    fn read_done(
        &self,
        buffer: &'static mut [u8],
        length: usize,
        mut error: Result<(), ErrorCode>,
    ) {
        if let Some(pid) = self.current_app.take() {
            let _ = self.apps.enter(pid, |_, kernel_data| {
                let _ = kernel_data
                    .get_readwrite_processbuffer(rw_allow::READ)
                    .and_then(|app_buf| {
                        app_buf.mut_enter(|app_data| {
                            let read_len = length.min(app_data.len());
                            if error.is_ok() {
                                match buffer.get(..read_len) {
                                    Some(data) => app_data[..read_len].copy_from_slice(data),
                                    None => error = Err(ErrorCode::SIZE),
                                }
                            }
                        })
                    });

                kernel_data
                    .schedule_upcall(
                        upcall::READ_DONE,
                        (length, error.err().map(|e| e as usize).unwrap_or(0), 0),
                    )
                    .ok();
            });
        }
        // The process may have exited since its request was accepted.
        self.buffer.replace(buffer);
        self.check_queue();
    }

    fn seek_done(&self, error: Result<(), ErrorCode>) {
        if let Some(pid) = self.current_app.take() {
            let _ = self.apps.enter(pid, move |_, kernel_data| {
                kernel_data
                    .schedule_upcall(
                        upcall::SEEK_DONE,
                        (error.err().map(|e| e as usize).unwrap_or(0), 0, 0),
                    )
                    .ok();
            });
        }
        self.check_queue();
    }
}

impl LogWriteClient for LoggingDriver<'_> {
    fn append_done(
        &self,
        buffer: &'static mut [u8],
        length: usize,
        records_lost: bool,
        error: Result<(), ErrorCode>,
    ) {
        self.buffer.replace(buffer);
        if let Some(pid) = self.current_app.take() {
            let _ = self.apps.enter(pid, move |_, kernel_data| {
                kernel_data
                    .schedule_upcall(
                        upcall::APPEND_DONE,
                        (
                            length,
                            records_lost as usize,
                            error.err().map(|e| e as usize).unwrap_or(0),
                        ),
                    )
                    .ok();
            });
        }

        self.check_queue();
    }

    fn sync_done(&self, error: Result<(), ErrorCode>) {
        if let Some(pid) = self.current_app.take() {
            let _ = self.apps.enter(pid, move |_, kernel_data| {
                kernel_data
                    .schedule_upcall(
                        upcall::SYNC_DONE,
                        (error.err().map(|e| e as usize).unwrap_or(0), 0, 0),
                    )
                    .ok();
            });
        }
        self.check_queue();
    }

    fn erase_done(&self, error: Result<(), ErrorCode>) {
        if let Some(pid) = self.current_app.take() {
            let _ = self.apps.enter(pid, move |_, kernel_data| {
                kernel_data
                    .schedule_upcall(
                        upcall::ERASE_DONE,
                        (error.err().map(|e| e as usize).unwrap_or(0), 0, 0),
                    )
                    .ok();
            });
        }
        self.check_queue();
    }
}

pub struct LoggingFlashDriver<'a> {
    driver: LoggingDriver<'a>,
}

impl<'a> LoggingFlashDriver<'a> {
    pub fn new(
        log: &'a dyn LogReadWrite<'a>,
        driver_num: usize,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        buffer: &'static mut [u8],
    ) -> Self {
        Self {
            driver: LoggingDriver::new(log, driver_num, grant, buffer),
        }
    }

    pub fn get_driver_num(&self) -> usize {
        self.driver.get_driver_num()
    }
}

impl SyscallDriver for LoggingFlashDriver<'_> {
    fn command(
        &self,
        command_num: usize,
        arg1: usize,
        arg2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        let operation = match command_num {
            0 => return CommandReturn::success(),
            logging_cmd::GET_CAP => return self.driver.capacity(),
            logging_cmd::READ => LoggingOps::Read,
            logging_cmd::APPEND => LoggingOps::Append,
            logging_cmd::SEEK => LoggingOps::Seek,
            logging_cmd::SYNC => LoggingOps::Sync,
            logging_cmd::ERASE => LoggingOps::Erase,
            _ => return CommandReturn::failure(ErrorCode::NOSUPPORT),
        };
        self.driver.dispatch(operation, processid, arg1, arg2)
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.driver.allocate_grant(processid)
    }
}

impl LogReadClient for LoggingFlashDriver<'_> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize, error: Result<(), ErrorCode>) {
        self.driver.read_done(buffer, length, error);
    }

    fn seek_done(&self, error: Result<(), ErrorCode>) {
        self.driver.seek_done(error);
    }
}

impl LogWriteClient for LoggingFlashDriver<'_> {
    fn append_done(
        &self,
        buffer: &'static mut [u8],
        length: usize,
        records_lost: bool,
        error: Result<(), ErrorCode>,
    ) {
        self.driver.append_done(buffer, length, records_lost, error);
    }

    fn sync_done(&self, error: Result<(), ErrorCode>) {
        self.driver.sync_done(error);
    }

    fn erase_done(&self, error: Result<(), ErrorCode>) {
        self.driver.erase_done(error);
    }
}

pub struct LoggingRamDriver<'a> {
    driver: LoggingDriver<'a>,
}

impl<'a> LoggingRamDriver<'a> {
    pub fn new(
        log: &'a dyn LogReadWrite<'a>,
        driver_num: usize,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        buffer: &'static mut [u8],
    ) -> Self {
        Self {
            driver: LoggingDriver::new(log, driver_num, grant, buffer),
        }
    }

    pub fn get_driver_num(&self) -> usize {
        self.driver.get_driver_num()
    }
}

impl SyscallDriver for LoggingRamDriver<'_> {
    fn command(
        &self,
        command_num: usize,
        arg1: usize,
        arg2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        let operation = match command_num {
            0 => return CommandReturn::success(),
            logging_cmd::GET_CAP => return self.driver.capacity(),
            logging_cmd::READ => LoggingOps::Read,
            logging_cmd::APPEND => LoggingOps::Append,
            logging_cmd::SEEK => LoggingOps::Seek,
            logging_cmd::ERASE => LoggingOps::Erase,
            _ => return CommandReturn::failure(ErrorCode::NOSUPPORT),
        };
        self.driver.dispatch(operation, processid, arg1, arg2)
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.driver.allocate_grant(processid)
    }
}

impl LogReadClient for LoggingRamDriver<'_> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize, error: Result<(), ErrorCode>) {
        self.driver.read_done(buffer, length, error);
    }

    fn seek_done(&self, error: Result<(), ErrorCode>) {
        self.driver.seek_done(error);
    }
}

impl LogWriteClient for LoggingRamDriver<'_> {
    fn append_done(
        &self,
        buffer: &'static mut [u8],
        length: usize,
        records_lost: bool,
        error: Result<(), ErrorCode>,
    ) {
        self.driver.append_done(buffer, length, records_lost, error);
    }

    fn sync_done(&self, error: Result<(), ErrorCode>) {
        self.driver.sync_done(error);
    }

    fn erase_done(&self, error: Result<(), ErrorCode>) {
        self.driver.erase_done(error);
    }
}
