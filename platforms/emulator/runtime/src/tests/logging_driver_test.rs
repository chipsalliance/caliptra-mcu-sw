// Licensed under the Apache-2.0 license

//! Held Log HIL completions make syscall queue tests independent of deferred-call timing.
//! Grants, process buffers, upcalls and process termination use the real Tock kernel.

use core::cell::Cell;
use kernel::hil::log::{LogRead, LogReadClient, LogWrite, LogWriteClient};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{ErrorCode, ProcessId};

pub const LOG_DRIVER: usize = 0x9001_f000;
pub const CONTROL_DRIVER: usize = LOG_DRIVER + 1;
pub const EXIT_LOG_DRIVER: usize = LOG_DRIVER + 2;
pub const EXIT_CONTROL_DRIVER: usize = LOG_DRIVER + 3;

pub struct ControlledLog {
    kernel: &'static kernel::Kernel,
    read_client: OptionalCell<&'static dyn LogReadClient>,
    write_client: OptionalCell<&'static dyn LogWriteClient>,
    buffer: TakeCell<'static, [u8]>,
    operation: Cell<usize>,
    length: Cell<usize>,
    reject: Cell<bool>,
    calls: Cell<u32>,
    exiting_process: OptionalCell<ProcessId>,
}

impl ControlledLog {
    pub fn new(kernel: &'static kernel::Kernel) -> Self {
        Self {
            kernel,
            read_client: OptionalCell::empty(),
            write_client: OptionalCell::empty(),
            buffer: TakeCell::empty(),
            operation: Cell::new(0),
            length: Cell::new(0),
            reject: Cell::new(false),
            calls: Cell::new(0),
            exiting_process: OptionalCell::empty(),
        }
    }

    fn start(&self, operation: usize) -> Result<(), ErrorCode> {
        self.calls.set(self.calls.get() + 1);
        if self.reject.get() {
            return Err(ErrorCode::FAIL);
        }
        assert_eq!(self.operation.replace(operation), 0);
        Ok(())
    }

    fn complete(&self) {
        match self.operation.replace(0) {
            1 => {
                let buffer = self.buffer.take().unwrap();
                buffer[..self.length.get()].fill(0xa5);
                self.read_client
                    .unwrap_or_panic()
                    .read_done(buffer, self.length.get(), Ok(()));
            }
            2 => self.write_client.unwrap_or_panic().append_done(
                self.buffer.take().unwrap(),
                self.length.get(),
                false,
                Ok(()),
            ),
            3 => self.read_client.unwrap_or_panic().seek_done(Ok(())),
            4 => self.write_client.unwrap_or_panic().sync_done(Ok(())),
            5 => self.write_client.unwrap_or_panic().erase_done(Ok(())),
            _ => panic!("No held logging operation"),
        }
    }
}

impl LogRead<'static> for ControlledLog {
    type EntryID = usize;

    fn set_read_client(&'static self, client: &'static dyn LogReadClient) {
        self.read_client.set(client);
    }

    fn read(
        &self,
        buffer: &'static mut [u8],
        length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if let Err(error) = self.start(1) {
            return Err((error, buffer));
        }
        self.length.set(length);
        self.buffer.replace(buffer);
        Ok(())
    }

    fn log_start(&self) -> usize {
        0
    }
    fn log_end(&self) -> usize {
        1
    }
    fn next_read_entry_id(&self) -> usize {
        0
    }
    fn get_size(&self) -> usize {
        1024
    }
    fn seek(&self, _: usize) -> Result<(), ErrorCode> {
        self.start(3)
    }
}

impl LogWrite<'static> for ControlledLog {
    fn set_append_client(&'static self, client: &'static dyn LogWriteClient) {
        self.write_client.set(client);
    }

    fn append(
        &self,
        buffer: &'static mut [u8],
        length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if let Err(error) = self.start(2) {
            return Err((error, buffer));
        }
        self.length.set(length);
        self.buffer.replace(buffer);
        Ok(())
    }

    fn sync(&self) -> Result<(), ErrorCode> {
        self.start(4)
    }
    fn erase(&self) -> Result<(), ErrorCode> {
        self.start(5)
    }
}

impl SyscallDriver for ControlledLog {
    fn allocate_grant(&self, _: ProcessId) -> Result<(), kernel::process::Error> {
        Ok(())
    }

    fn command(
        &self,
        command: usize,
        arg1: usize,
        _: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command {
            0 => CommandReturn::success_u32(self.operation.get() as u32),
            1 => {
                self.complete();
                CommandReturn::success()
            }
            2 => {
                self.reject.set(arg1 != 0);
                CommandReturn::success()
            }
            3 => CommandReturn::success_u32(self.calls.get()),
            4 => {
                self.exiting_process.set(processid);
                CommandReturn::success()
            }
            5 => {
                let capability =
                    kernel::create_capability!(kernel::capabilities::ProcessManagementCapability);
                let exited = self.exiting_process.map_or(false, |pid| {
                    self.kernel.process_map_or_external(
                        false,
                        pid,
                        |process| {
                            process.get_state() == kernel::process::State::Terminated
                                && process.pending_tasks() == 0
                        },
                        &capability,
                    )
                });
                CommandReturn::success_u32(exited as u32)
            }
            // Inspect the actual kernel transfer buffer before append completion.
            6 => self
                .buffer
                .map_or(CommandReturn::failure(ErrorCode::RESERVE), |buffer| {
                    CommandReturn::success_u32(
                        (self.operation.get() == 2
                            && buffer[..self.length.get()]
                                .iter()
                                .all(|byte| *byte == arg1 as u8)) as u32,
                    )
                }),
            7 => {
                let capability =
                    kernel::create_capability!(kernel::capabilities::ProcessManagementCapability);
                self.kernel.process_each_capability(&capability, |process| {
                    caliptra_mcu_romtime::println!(
                        "[logging-driver] process {} state {:?}, pending {}, registered victim {}",
                        process.get_process_name(),
                        process.get_state(),
                        process.pending_tasks(),
                        self.exiting_process.contains(&process.processid())
                    );
                });
                CommandReturn::success_u32(self.exiting_process.is_some() as u32)
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }
}
