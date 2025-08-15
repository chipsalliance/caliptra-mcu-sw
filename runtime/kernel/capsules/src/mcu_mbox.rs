// Licensed under the Apache-2.0 license

use core::cell::Cell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::OptionalCell;
use kernel::{ErrorCode, ProcessId};
use mcu_mbox_comm::hil;
use mcu_mbox_comm::hil::{Mailbox, MailboxClient, MailboxStatus};
use romtime::println;

pub const MCU_MBOX0_DRIVER_NUM: u32 = 0x8000_0010;

/// Command IDs
/// - `0` - Command to check if the MCU mailbox syscall driver exists
/// - `1` - Receive request
/// - `2` - Receive response
mod command {
    pub const EXISTS: u32 = 0;
    pub const RECEIVE_REQUEST: u32 = 1;
    pub const SEND_RESPONSE: u32 = 2;
}

// Read-only buffer to read the response from.
mod allow_ro {
    pub const RESPONSE: u32 = 0;
    pub const COUNT: u8 = 1;
}

// Read-write buffer to write the received request to.
mod allow_rw {
    pub const REQUEST: u32 = 0;
    pub const COUNT: u8 = 1;
}

// Upcalls
mod upcall {
    pub const REQUEST_RECEIVED: u32 = 0;
    pub const RESPONSE_SENT: u32 = 1;
    pub const COUNT: u8 = 2;
}

#[derive(Default)]
pub struct App {
    waiting_rx: Cell<bool>, // Indicates if a request is waiting to be received
    pending_tx: Cell<bool>, // Indicates if a response is pending to be sent
    arg1: usize,
    _arg2: usize,
}

pub struct McuMboxDriver<'a, T: mcu_mbox_comm::hil::Mailbox<'a>> {
    driver: &'a T, // Underlying MCU mailbox driver
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    current_app: OptionalCell<ProcessId>,
}

impl McuMboxDriver<'a, T: mcu_mbox_comm::hil::Mailbox<'a>> {
    pub fn new(
        driver: &'a T,
        apps: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Self {
        McuMboxDriver {
            driver,
            apps,
            current_app: OptionalCell::empty(),
        }
    }

    /// Transmit the app buffer as u32 dwords on-the-fly using the iterator-based HIL.
    fn start_transmit(
        &self,
        app_buf: &ReadableProcessSlice,
        status: MailboxStatus,
    ) -> Result<(), ErrorCode> {
        let data_len_bytes = app_buf.len();
        if data_len_bytes % 4 != 0 {
            return Err(ErrorCode::INVAL);
        }
        let dword_count = data_len_bytes / 4;
        let dword_iter = app_buf.chunks(4).map(|chunk| {
            let mut dword = [0u8; 4];
            dword.copy_from_slice(chunk);
            u32::from_le_bytes(dword)
        });
        self.driver.send_response(dword_iter, dword_count, status)
    }

    pub fn send_app_response(
        &self,
        process_id: ProcessId,
        app: &App,
        kernel_data: &GrantKernelData<'_, App>,
        status: MailboxStatus,
    ) -> Result<usize, ErrorCode> {
        self.current_app.set(process_id);

        let _result = kernel_data
            .get_readonly_processbuffer(ro_allow::RESPONSE)
            .map_err(|e| {
                println!(
                    "MCU_MBOX_CAPSULE: Error getting ReadOnlyProcessBuffer buffer: {:?}",
                    e
                );
                ErrorCode::INVAL
            })
            .and_then(|tx_buf| {
                tx_buf
                    .enter(|app_buf| self.start_transmit(app_buf, status))
                    .map_err(|e| {
                        println!(
                            "MCU_MBOX_CAPSULE: Error getting application tx buffer: {:?}",
                            e
                        );
                        ErrorCode::FAIL
                    })
            })?;

        app.pending_tx.set(true);
        Ok(())
    }
}

// Implement the SyscallDriver trait for McuMboxDriver
impl<'a, T: mcu_mbox_comm::hil::Mailbox<'a>> SyscallDriver for McuMboxDriver<'a, T> {
    fn command(
        &self,
        command_num: usize,
        arg1: usize,
        _arg2: usize,
        process_id: ProcessId,
    ) -> CommandReturn {
        match command_num {
            0 => CommandReturn::success(),
            1 => {
                // Receive Request Message
                let res = self.apps.enter(process_id, |app, _| {
                    app.waiting_rx.set(true);
                });

                match res {
                    Ok(_) => CommandReturn::success(),
                    Err(err) => CommandReturn::failure(err.into()),
                }
            }
            2 => {
                // Send response, arg1 is MailboxStatus as usize
                let status = match arg1 {
                    0 => MailboxStatus::Busy,
                    1 => MailboxStatus::DataReady,
                    2 => MailboxStatus::Complete,
                    3 => MailboxStatus::Failure,
                    _ => MailboxStatus::Failure,
                };
                let result = self
                    .apps
                    .enter(process_id, |app, kernel_data| {
                        if app.pending_tx.get() {
                            return Err(ErrorCode::BUSY);
                        }
                        self.send_app_response(process_id, app, kernel_data, status)
                    })
                    .map_err(|err| {
                        println!("MCU_MBOX_CAPSULE: Error sending response {:?}", err);
                        err.into()
                    });

                match result {
                    Ok(_) => CommandReturn::success(),
                    Err(err) => {
                        println!("MCU_MBOX_CAPSULE: Error sending response: {:?}", err);
                        CommandReturn::failure(err)
                    }
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(process_id, |_, _| {})
    }
}

// Implement the MailboxClient trait for McuMboxDriver

impl<'a, T: hil::Mailbox<'a>> MailboxClient for McuMboxDriver<'a, T> {
    fn request_received(&self, command: u32, rx_buf: &'static mut [u32], dw_len: usize) {
        // sanity check buffer len
        if dw_len > rx_buf.len() {
            println!("MCU_MBOX_CAPSULE: Received request with invalid length {}", dw_len);

            // Restore driver buffers. TODO: move set_rx_buffer to trait Mailbox
            self.driver.set_rx_buffer(rx_buf);
            return;
        }

        self.apps.each(|app, kernel_data| {
            if app.waiting_rx.get() {
                if let Ok(rw_buf) = kernel_data.get_writeable_processbuffer(rw_allow::REQUEST) {
                    rw_buf.mut_enter(|buf| {
                        let n = dw_len.min(buf.len() / 4);
                        for i in 0..n {
                            let bytes = rx_buf[i].to_le_bytes();
                            buf[i * 4..i * 4 + 4].copy_from_slice(&bytes);
                        }
                    });
                }
                app.waiting_rx.set(false);

                kernel_data.schedule_upcall(upcall::REQUEST_RECEIVED, (command as usize, dw_len * 4, 0));
            } else {
                println!("MCU_MBOX_CAPSULE: Request received but no app waiting for it.");
            }
        });

        // Restore driver buffers
        self.driver.set_rx_buffer(rx_buf);
    }

    fn response_received(&self, _status: MailboxStatus, _rx_buf: &'static mut [u32], _dw_len: usize) {
        unimplemented!("MCU mailbox driver is receiver-mode only");
    }

    fn send_done(&self, result: Result<(), ErrorCode>) {
        self.apps.each(|app, kernel_data| {
            if app.pending_tx.get() {
                app.pending_tx.set(false);
                let code = match result {
                    Ok(()) => 0,
                    Err(e) => e.into(),
                };
                kernel_data.schedule_upcall(upcall::RESPONSE_SENT, (code, 0, 0));
            }
        });
    }
}