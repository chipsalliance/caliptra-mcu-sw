// Licensed under the Apache-2.0 license

//! Capsule for MCU Mailbox 0 syscall driver (Receiver Mode)

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{debug, ErrorCode, ProcessId};
use mcu_mbox_hil::hil::{Mailbox, MailboxClient, MailboxStatus};

/// Maximum chunk size for request/response transfers.
pub const CHUNK_SIZE: usize = 256;

/// Syscall driver number for MCU Mailbox 0
pub const DRIVER_NUM: usize = 0x8000_0010;

pub enum McuReceiverOps {
    ReceiveRequest = 1,
    SendResponse = 2,
}

/// Upcall and buffer IDs for MCU mailbox
mod upcall {
    pub const REQUEST_RECEIVED: u32 = 0;
    pub const RESPONSE_SENT: u32 = 1;
    pub const COUNT: u8 = 2;
}

mod ro_allow {
    pub const RESPONSE: usize = 0;
    pub const COUNT: u8 = 1;
}
mod rw_allow {
    pub const REQUEST: usize = 0;
    pub const COUNT: u8 = 1;
}

/// Capsule implementing the MCU Mailbox 0 syscall interface
pub struct McuMbox0Capsule<'a, M: Mailbox<'a>> {
    mailbox: &'a M,
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    current_app: OptionalCell<ProcessId>,
}

/// Per-app data
#[derive(Default)]
pub struct App {}

impl<'a, M: Mailbox<'a>> McuMbox0Capsule<'a, M> {
    pub fn new(
        mailbox: &'a M,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Self {
        Self {
            mailbox,
            apps: grant,
            current_app: OptionalCell::empty(),
        }
    }

    /// Enqueue a receive request from the mailbox (receiver mode only)
    fn receive_request(&self, processid: ProcessId) -> Result<(), ErrorCode> {
        if self.current_app.is_some() {
            return Err(ErrorCode::BUSY);
        }
        self.apps.enter(processid, |_app, kernel_data| {
            kernel_data
                .get_readwrite_processbuffer(rw_allow::REQUEST)
                .map_err(|_| ErrorCode::FAIL)
                .and_then(|rw_buffer| {
                    rw_buffer.mut_enter(|app_buffer| self.mailbox.handle_incoming_data(app_buffer))
                })
        })?;
        self.current_app.set(processid);
        Ok(())
    }

    /// Send a response to the mailbox host (receiver mode only)
    fn send_response(&self, processid: ProcessId) -> Result<usize, ErrorCode> {
        self.apps.enter(processid, |_app, kernel_data| {
            kernel_data
                .get_readonly_processbuffer(ro_allow::RESPONSE)
                .map_err(|_| ErrorCode::FAIL)
                .and_then(|ro_buffer| {
                    ro_buffer.enter(|app_buffer| self.mailbox.send_response(app_buffer))
                })
        })
    }

    fn complete_request(&self, processid: ProcessId, result: Result<usize, ErrorCode>) {
        let _ = self.apps.enter(processid, |_app, kernel_data| {
            let code = match result {
                Ok(len) => (len, 0, 0),
                Err(e) => (0, e as usize, 0),
            };
            let _ = kernel_data.schedule_upcall(upcall::REQUEST_RECEIVED as usize, code);
        });
        self.current_app.take();
    }

    fn complete_response(&self, processid: ProcessId, result: Result<usize, ErrorCode>) {
        let _ = self.apps.enter(processid, |_app, kernel_data| {
            let code = match result {
                Ok(len) => (len, 0, 0),
                Err(e) => (0, e as usize, 0),
            };
            let _ = kernel_data.schedule_upcall(upcall::RESPONSE_SENT as usize, code);
        });
    }
}

impl<'a, M: Mailbox<'a>> SyscallDriver for McuMbox0Capsule<'a, M> {
    fn command(
        &self,
        command_num: usize,
        _arg1: usize,
        _arg2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_num {
            1 => {
                let res = self.receive_request(processid);
                self.complete_request(processid, res.map(|_| 0));
                match res {
                    Ok(_) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            2 => {
                let res = self.send_response(processid);
                self.complete_response(processid, res);
                match res {
                    Ok(len) => CommandReturn::success_u32(len as u32),
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

impl<'a, M: Mailbox<'a>> MailboxClient for McuMbox0Capsule<'a, M> {
    fn data_available(&self, command: u32, length: usize) {
        // Find app and schedule upcall
    }
    fn command_complete(&self, status: MailboxStatus) {
        // Find app and schedule upcall
        unreachable!("Command complete not used in Receiver Mode");
    }
    fn mailbox_error(&self, error: ErrorCode) {
        // Find app and schedule upcall
    }
}
