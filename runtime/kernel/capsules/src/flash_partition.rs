// Licensed under the Apache-2.0 license

//! This provides  the flash partition syscall driver

use core::cmp;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{ErrorCode, ProcessId};

pub const BUF_LEN: usize = 512;

/// IDs for subscribed upcalls.
mod upcall {
    /// Read done callback.
    pub const READ_DONE: usize = 0;
    /// Write done callback.
    pub const WRITE_DONE: usize = 1;
    /// Erase done callback
    pub const ERASE_DONE: usize = 2;
    /// Number of upcalls.
    pub const COUNT: u8 = 3;
}

/// Ids for read-only allow buffers
mod ro_allow {
    /// Setup a buffer to write bytes to the flash storage.
    pub const WRITE: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

/// Ids for read-write allow buffers
mod rw_allow {
    /// Setup a buffer to read from the flash storage into.
    pub const READ: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

#[derive(Clone, Copy, PartialEq)]
pub enum FlashStorageCommand {
    Read,
    Write,
    Erase,
}

pub struct App {
    pending_command: bool,
    command: FlashStorageCommand,
    offset: usize,
    length: usize,
}

impl Default for App {
    fn default() -> App {
        App {
            pending_command: false,
            command: FlashStorageCommand::Read,
            offset: 0,
            length: 0,
        }
    }
}

pub struct FlashPartition<'a> {
    // The underlying flash storage driver.
    driver: &'a dyn flash_driver::hil::FlashStorage<'a>,
    // The driver number for this partition.
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
    // Which app is currently using the storage.
    current_app: OptionalCell<ProcessId>,
    // Offset in the physical storage where this partition starts.
    start_address: usize,
    // Length of this partition.
    length: usize,
}

impl<'a> FlashPartition<'a> {
    pub fn new(
        driver: &'a dyn flash_driver::hil::FlashStorage<'a>,
        driver_num: usize,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        start_address: usize,
        length: usize,
        buffer: &'static mut [u8],
    ) -> FlashPartition<'a> {
        FlashPartition {
            driver,
            driver_num,
            apps: grant,
            buffer: TakeCell::new(buffer),
            current_app: OptionalCell::empty(),
            start_address,
            length,
        }
    }

    // Get the Driver number for this partition.
    pub fn get_driver_num(&self) -> usize {
        self.driver_num
    }

    // Check if any command is pending. If not, this command is executed.
    // If so, this command is queued and will be run when the pending
    // command is completed.
    fn enqueue_command(
        &self,
        command: FlashStorageCommand,
        offset: usize,
        length: usize,
        processid: Option<ProcessId>,
    ) -> Result<(), ErrorCode> {
        // Do bounds check. Userspace sees memory that starts at address 0 even if it
        // is offset in the physical memory.
        if offset >= self.length || length > self.length || offset + length > self.length {
            return Err(ErrorCode::INVAL);
        }

        if self.buffer.is_none() {
            return Err(ErrorCode::RESERVE);
        }

        processid.map_or(Err(ErrorCode::FAIL), |processid| {
            self.apps
                .enter(processid, |app, kernel_data| {
                    // Get the length of the correct allowed buffer.
                    let allow_buf_len = match command {
                        FlashStorageCommand::Read => kernel_data
                            .get_readwrite_processbuffer(rw_allow::READ)
                            .map_or(0, |read| read.len()),
                        FlashStorageCommand::Write => kernel_data
                            .get_readonly_processbuffer(ro_allow::WRITE)
                            .map_or(0, |read| read.len()),
                        _ => 0,
                    };

                    if command != FlashStorageCommand::Erase && allow_buf_len == 0 {
                        return Err(ErrorCode::RESERVE);
                    }

                    // Shorten the length if the application gave us nowhere to
                    // put it.
                    let active_len = if let FlashStorageCommand::Erase = command {
                        length
                    } else {
                        cmp::min(length, allow_buf_len)
                    };

                    // Check if this command can be executed immediately or queued.
                    if self.current_app.is_none() {
                        // No app is currently using the underlying storage.
                        // Mark this app as active, and then execute the command.
                        self.current_app.set(processid);

                        // Need to copy bytes if this is a write.
                        if command == FlashStorageCommand::Write {
                            let _ = kernel_data
                                .get_readonly_processbuffer(ro_allow::WRITE)
                                .and_then(|write| {
                                    write.enter(|app_buffer| {
                                        self.buffer.map(|kernel_buffer| {
                                            // Check that the internal buffer and the buffer that was
                                            // allowed are long enough.
                                            let write_len =
                                                cmp::min(active_len, kernel_buffer.len());

                                            let d = &app_buffer[0..write_len];
                                            d.copy_to_slice(&mut kernel_buffer[0..write_len]);
                                        });
                                    })
                                });
                        }

                        self.userspace_call_driver(command, offset, active_len)
                            .inspect_err(|_| {
                                // If the driver call failed immediately, clear current_app
                                // so other apps can proceed.
                                self.current_app.clear();
                            })
                    } else if app.pending_command {
                        // No more room in the queue, nowhere to store this request.
                        Err(ErrorCode::NOMEM)
                    } else {
                        // Queue this request.
                        app.pending_command = true;
                        app.command = command;
                        app.offset = offset;
                        app.length = active_len;
                        Ok(())
                    }
                })
                .unwrap_or_else(|err| Err(err.into()))
        })
    }

    fn userspace_call_driver(
        &self,
        command: FlashStorageCommand,
        offset: usize,
        length: usize,
    ) -> Result<(), ErrorCode> {
        // Calculate where we want to actually read from in the physical
        // storage.
        let physical_address = offset + self.start_address;
        match command {
            FlashStorageCommand::Erase => self.driver.erase(physical_address, length),
            FlashStorageCommand::Read | FlashStorageCommand::Write => {
                self.buffer
                    .take()
                    .map_or(Err(ErrorCode::RESERVE), |buffer| {
                        // Check that the internal buffer and the buffer that was
                        // allowed are long enough.
                        let active_len = cmp::min(length, buffer.len());

                        if command == FlashStorageCommand::Read {
                            self.driver.read(buffer, physical_address, active_len)
                        } else {
                            self.driver.write(buffer, physical_address, active_len)
                        }
                    })
            }
        }
    }

    fn check_queue(&self) {
        // Check if there are any pending command.
        for cntr in self.apps.iter() {
            let processid = cntr.processid();
            let started_command = cntr.enter(|app, _| {
                if app.pending_command {
                    app.pending_command = false;
                    self.current_app.set(processid);
                    matches!(
                        self.userspace_call_driver(app.command, app.offset, app.length),
                        Ok(())
                    )
                } else {
                    false
                }
            });
            if started_command {
                break;
            }
        }
    }
}

impl flash_driver::hil::FlashStorageClient for FlashPartition<'_> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize) {
        // Switch on which user of this capsule generated this callback.
        if let Some(processid) = self.current_app.take() {
            let _ = self.apps.enter(processid, move |_, kernel_data| {
                // Need to copy in the contents of the buffer
                let _ = kernel_data
                    .get_readwrite_processbuffer(rw_allow::READ)
                    .and_then(|read| {
                        read.mut_enter(|app_buffer| {
                            let read_len = cmp::min(app_buffer.len(), length);

                            let d = &app_buffer[0..read_len];
                            d.copy_from_slice(&buffer[0..read_len]);
                        })
                    });

                // Replace the buffer that is used to do this read.
                self.buffer.replace(buffer);

                // And then signal the app.
                kernel_data
                    .schedule_upcall(upcall::READ_DONE, (length, 0, 0))
                    .ok();
            });
        };

        self.check_queue();
    }

    fn write_done(&self, buffer: &'static mut [u8], length: usize) {
        // Switch on which user of this capsule generated this callback.
        if let Some(processid) = self.current_app.take() {
            let _ = self.apps.enter(processid, move |_, kernel_data| {
                // Replace the buffer that is used to do this write.
                self.buffer.replace(buffer);

                // Signal the app.
                kernel_data
                    .schedule_upcall(upcall::WRITE_DONE, (length, 0, 0))
                    .ok();
            });
        };

        self.check_queue();
    }

    fn erase_done(&self, length: usize) {
        // Switch on which user of this capsule generated this callback.
        if let Some(processid) = self.current_app.take() {
            let _ = self.apps.enter(processid, move |_, kernel_data| {
                // Signal the app.
                kernel_data
                    .schedule_upcall(upcall::ERASE_DONE, (length, 0, 0))
                    .ok();
            });
        };

        self.check_queue();
    }
}

/// Provide an interface for userland.
impl SyscallDriver for FlashPartition<'_> {
    /// Command interface.
    ///
    /// Commands are selected by the lowest 8 bits of the first argument.
    ///
    /// ### `command_num`
    ///
    /// - `0`: Return Ok(()) if this driver is included on the platform.
    /// - `1`: Return the number of bytes available to userspace.
    /// - `2`: Start a read
    /// - `3`: Start a write
    /// - `4`: Start an erase
    /// - `5`: Return the chunk size for reads and writes
    fn command(
        &self,
        command_num: usize,
        offset: usize,
        length: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_num {
            0 => CommandReturn::success(),

            1 => {
                // Return the number of bytes available to userspace.
                CommandReturn::success_u32(self.length as u32)
            }

            2 => {
                // Issue a read command
                let res = self.enqueue_command(
                    FlashStorageCommand::Read,
                    offset,
                    length,
                    Some(processid),
                );

                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            3 => {
                // Issue a write command
                let res = self.enqueue_command(
                    FlashStorageCommand::Write,
                    offset,
                    length,
                    Some(processid),
                );

                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            4 => {
                // Issue an erase command
                let res = self.enqueue_command(
                    FlashStorageCommand::Erase,
                    offset,
                    length,
                    Some(processid),
                );

                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            5 => {
                // Return the chunk size for reads and writes
                CommandReturn::success_u32(BUF_LEN as u32)
            }

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
