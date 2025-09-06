// Licensed under the Apache-2.0 license

use core::cell::Cell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::OptionalCell;
use kernel::{ErrorCode, ProcessId};
use mcu_mbox_comm::hil;
use romtime::println;

pub const MCU_MBOX0_DRIVER_NUM: usize = 0x8000_0010;

// Read-only buffer to read the response from.
mod ro_allow {
    pub const RESPONSE: usize = 0;
    pub const COUNT: u8 = 1;
}

// Read-write buffer to write the received request to.
mod rw_allow {
    pub const REQUEST: usize = 0;
    pub const COUNT: u8 = 1;
}

// Upcalls
mod upcall {
    pub const REQUEST_RECEIVED: usize = 0;
    pub const RESPONSE_SENT: usize = 1;
    pub const COUNT: u8 = 2;
}

#[derive(Default)]
pub struct App {
    waiting_rx: Cell<bool>, // Indicates if a request is waiting to be received
    pending_tx: Cell<bool>, // Indicates if a response is pending to be sent
}

pub struct McuMboxDriver<'a, T: hil::Mailbox<'a>> {
    driver: &'a T, // Underlying MCU mailbox driver
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    current_app: OptionalCell<ProcessId>,
}

impl<'a, T: hil::Mailbox<'a>> McuMboxDriver<'a, T> {
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

    fn start_transmit(
        &self,
        app_buf: &ReadableProcessSlice,
        status: hil::MailboxStatus,
    ) -> Result<(), ErrorCode> {
        let data_len_bytes = app_buf.len();
        let dword_count = data_len_bytes.div_ceil(4);

        self.driver.send_response(
            (0..dword_count).map(|i| {
                let start = i * 4;
                let end = core::cmp::min(start + 4, data_len_bytes);
                let mut dword = [0u8; 4];
                app_buf[start..end].copy_to_slice(&mut dword[..end - start]);
                u32::from_le_bytes(dword)
            }),
            data_len_bytes,
            status,
        )
    }

    pub fn send_app_response(
        &self,
        process_id: ProcessId,
        app: &App,
        kernel_data: &GrantKernelData<'_>,
        status: hil::MailboxStatus,
    ) -> Result<(), ErrorCode> {
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

impl<'a, T: hil::Mailbox<'a>> hil::MailboxClient for McuMboxDriver<'a, T> {
    fn request_received(&self, command: u32, rx_buf: &'static mut [u32], dlen: usize) {
        if let Some(_process_id) = self.current_app.take() {
            let dw_len = dlen.div_ceil(4);
            if dw_len > rx_buf.len() {
                println!(
                    "MCU_MBOX_CAPSULE: Received request with invalid length {}",
                    dw_len
                );
                self.driver.restore_rx_buffer(rx_buf);
                return;
            }

            let _ = self.apps.enter(_process_id, |app, kernel_data| {
                if app.waiting_rx.get() {
                    app.waiting_rx.set(false);
                } else {
                    println!("MCU_MBOX_CAPSULE: Application not waiting for request");
                    return;
                }

                let process_result : Result<Result<usize, ErrorCode>, ErrorCode> =
                    match kernel_data.get_readwrite_processbuffer(rw_allow::REQUEST) {
                        Ok(rw_buf) => {
                            let copy_len_dw = core::cmp::min(rw_buf.len() / 4, dw_len);
                            rw_buf
                                .mut_enter(|buf| {
                                    for (i, &data) in rx_buf.iter().enumerate().take(copy_len_dw) {
                                        let start = i * 4;
                                        let end = start + 4;
                                        let bytes = data.to_le_bytes();
                                        buf[start..end].copy_from_slice(&bytes);
                                    }
                                    Ok(core::cmp::min(copy_len_dw * 4, dlen))
                                })
                                .map_err(|e| {
                                    println!("MCU_MBOX_CAPSULE: Error entering WriteableProcessBuffer buffer: {:?}", e);
                                    e.into()
                                })
                        }
                        Err(err) => {
                            println!(
                                "MCU_MBOX_CAPSULE: Error getting WriteableProcessBuffer buffer: {:?}",
                                err
                            );
                            Err(ErrorCode::INVAL)
                        }
                    };

                match process_result  {
                    Ok(Ok(len)) => {
                        kernel_data
                            .schedule_upcall(upcall::REQUEST_RECEIVED, (command as usize, len, 0))
                            .ok();
                    }
                    Ok(Err(err)) => {
                        println!("MCU_MBOX_CAPSULE: Error copying data to app buffer: {:?}", err);
                    }
                    Err(err) => {
                        println!("MCU_MBOX_CAPSULE: Error while accessing app buffer: {:?}", err);
                    }
                }
            });
        }

        // Restore driver rx buffer
        self.driver.restore_rx_buffer(rx_buf);
    }

    fn response_received(
        &self,
        _status: hil::MailboxStatus,
        _rx_buf: &'static mut [u32],
        _dw_len: usize,
    ) {
        unimplemented!("MCU mailbox driver is receiver-mode only");
    }

    fn send_done(&self, result: Result<(), ErrorCode>) {
        if let Some(process_id) = self.current_app.take() {
            let _ = self.apps.enter(process_id, |app, kernel_data| {
                app.pending_tx.set(false);
                let code = match result {
                    Ok(()) => 0,
                    Err(e) => e.into(),
                };
                kernel_data
                    .schedule_upcall(upcall::RESPONSE_SENT, (code, 0, 0))
                    .ok();
            });
        }
    }
}

impl<'a, T: hil::Mailbox<'a>> SyscallDriver for McuMboxDriver<'a, T> {
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
                if self.current_app.is_some() {
                    return CommandReturn::failure(ErrorCode::BUSY);
                }
                // Receive request message
                let res = self.apps.enter(process_id, |app, _| {
                    if app.waiting_rx.get() {
                        return Err(ErrorCode::BUSY);
                    }
                    app.waiting_rx.set(true);
                    self.current_app.set(process_id);
                    Ok(())
                });

                match res {
                    Ok(_) => CommandReturn::success(),
                    Err(err) => CommandReturn::failure(err.into()),
                }
            }
            2 => {
                if self.current_app.is_some() {
                    return CommandReturn::failure(ErrorCode::BUSY);
                }
                // Prepare to send response; arg1 encodes MailboxStatus as usize
                let status = match arg1 {
                    0 => hil::MailboxStatus::Busy,
                    1 => hil::MailboxStatus::DataReady,
                    2 => hil::MailboxStatus::Complete,
                    3 => hil::MailboxStatus::Failure,
                    _ => return CommandReturn::failure(ErrorCode::INVAL),
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
