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

pub const MAX_DATA_SIZE_DWORDS: usize = 256; // Adjust size as needed
pub struct BufferedMessage {
    pub command: u32,
    pub data: [u32; MAX_DATA_SIZE_DWORDS], // Adjust size as needed
    pub dlen: usize,
    pub valid: bool,
}
impl Default for BufferedMessage {
    fn default() -> Self {
        BufferedMessage {
            command: 0,
            data: [0; MAX_DATA_SIZE_DWORDS],
            dlen: 0,
            valid: false,
        }
    }
}

#[derive(Default)]
pub struct App {
    waiting_rx: Cell<bool>, // Indicates if a request is waiting to be received
    pending_tx: Cell<bool>, // Indicates if a response is pending to be sent
    buffered_msg: BufferedMessage,
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

    fn start_transmit(&self, app_buf: &ReadableProcessSlice) -> Result<(), ErrorCode> {
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
        )
    }

    pub fn send_app_response(
        &self,
        process_id: ProcessId,
        app: &App,
        kernel_data: &GrantKernelData<'_>,
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
                    .enter(|app_buf| self.start_transmit(app_buf))
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

    fn buffer_message(&self, app: &mut App, command: u32, rx_buf: &[u32], dlen: usize) -> bool {
        let dw_len = dlen.div_ceil(4);
        if dw_len > app.buffered_msg.data.len() {
            // Message too large for buffer, do not store
            return false;
        }
        // Print warning if replacing an old message
        if app.buffered_msg.valid {
            println!("MCU_MBOX_CAPSULE: Warning - replacing old buffered message with new one");
        }
        // Always replace the old message with the new one
        app.buffered_msg.command = command;
        app.buffered_msg.dlen = dlen;
        app.buffered_msg.valid = true;
        let copy_len = dw_len;
        for i in 0..copy_len {
            app.buffered_msg.data[i] = rx_buf[i];
        }
        println!(
            "[xs debug]MCU_MBOX_CAPSULE: Buffered message cmd{}, len{}",
            command, dlen
        );
        true
    }

    fn deliver_message(
        &self,
        process_id: ProcessId,
        app: &mut App,
        kernel_data: &GrantKernelData<'_>,
    ) -> Result<(), ErrorCode> {
        if !app.buffered_msg.valid {
            return Err(ErrorCode::FAIL);
        }

        if app.waiting_rx.get() {
            app.waiting_rx.set(false);
        }

        let command = app.buffered_msg.command;
        let dlen = app.buffered_msg.dlen;
        let dw_len = dlen.div_ceil(4);

        let result = kernel_data
            .get_readwrite_processbuffer(rw_allow::REQUEST)
            .map_err(|e| {
                println!(
                    "MCU_MBOX_CAPSULE: deliver_message Error getting WriteableProcessBuffer buffer: {:?}",
                    e
                );
                ErrorCode::INVAL
            })
            .and_then(|rw_buf| {
                rw_buf.mut_enter(|buf| -> Result<usize, ErrorCode> {
                    let copy_len_dw = core::cmp::min(buf.len() / 4, dw_len);
                    for i in 0..copy_len_dw {
                        let start = i * 4;
                        let end = start + 4;
                        let bytes = app.buffered_msg.data[i].to_le_bytes();
                        buf[start..end].copy_from_slice(&bytes);
                    }
                    Ok(core::cmp::min(copy_len_dw * 4, dlen))
                }).map_err(|e| {
                    println!("MCU_MBOX_CAPSULE: deliver_message Error entering WriteableProcessBuffer buffer: {:?}", e);
                    ErrorCode::FAIL
                })
            });

        match result {
            Ok(Ok(len)) => {
                if let Err(e) = kernel_data
                    .schedule_upcall(upcall::REQUEST_RECEIVED, (command as usize, len, 0))
                {
                    println!("MCU_MBOX_CAPSULE: Error scheduling upcall: {:?}", e);
                    return Err(ErrorCode::FAIL);
                }
                //println!("[xs debug]MCU_MBOX_CAPSULE: Delivered buffered message to app: cmd{}, len{}", command, len);
            }
            Ok(Err(err)) => {
                println!(
                    "MCU_MBOX_CAPSULE: Error copying data to app buffer: {:?}",
                    err
                );
                return Err(err);
            }
            Err(err) => {
                println!(
                    "MCU_MBOX_CAPSULE: Error while accessing app buffer: {:?}",
                    err
                );
                return Err(err);
            }
        }

        // Invalidate the buffered message after delivery
        app.buffered_msg.valid = false;

        Ok(())
    }
}

impl<'a, T: hil::Mailbox<'a>> hil::MailboxClient for McuMboxDriver<'a, T> {
    fn request_received(&self, command: u32, rx_buf: &'static mut [u32], dlen: usize) {
        /*
        if let Some(process_id) = self.current_app.take() {
            let dw_len = dlen.div_ceil(4);
            if dw_len > rx_buf.len() {
                println!(
                    "MCU_MBOX_CAPSULE: Received request with invalid length {}",
                    dw_len
                );
                self.driver.restore_rx_buffer(rx_buf);
                return;
            }

            let _ = self.apps.enter(process_id, |app, kernel_data| {
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
        } else {
            println!(
                "MCU_MBOX_CAPSULE: No app is registered to receive request. Dropping request."
            );
        } */

        let dw_len = dlen.div_ceil(4);
        if dw_len > rx_buf.len() {
            println!(
                "MCU_MBOX_CAPSULE: Received request with invalid length {}",
                dw_len
            );
            self.driver.restore_rx_buffer(rx_buf);
            return;
        }
        // self.apps.each(|_, app, kernel_data|

        let _ = self.apps.each(|_, app, kernel_data| {
            if app.waiting_rx.get() {
                app.waiting_rx.set(false);
            } else {
                // Buffer the message for later delivery
                println!("MCU_MBOX_CAPSULE: Application not waiting for request, buffering message");
                self.buffer_message(app, command, rx_buf, dlen);
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
                //romtime::println!("[xs debug]MCU_MBOX_CAPSULE: Response sent upcall scheduled.");
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
                    println!("MCU_MBOX_CAPSULE: ERROR current_app is busy");
                    return CommandReturn::failure(ErrorCode::BUSY);
                }
                // Receive request message
                let res = self.apps.enter(process_id, |app, kernel_data| {
                    if app.waiting_rx.get() {
                        println!("MCU_MBOX_CAPSULE: ERROR App BUSY waiting for request");
                        return Err(ErrorCode::BUSY);
                    }
                    app.waiting_rx.set(true);
                    if app.buffered_msg.valid {
                        // Deliver buffered message immediately
                        self.deliver_message(process_id, app, kernel_data)?;
                    }
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
                /*
                // Prepare to send response; arg1 encodes MailboxStatus as usize
                let status = match arg1 {
                    0 => hil::MailboxStatus::Busy,
                    1 => hil::MailboxStatus::DataReady,
                    2 => hil::MailboxStatus::Complete,
                    3 => hil::MailboxStatus::Failure,
                    _ => return CommandReturn::failure(ErrorCode::INVAL),
                };
                */
                let result = self
                    .apps
                    .enter(process_id, |app, kernel_data| {
                        if app.pending_tx.get() {
                            return Err(ErrorCode::BUSY);
                        }
                        self.send_app_response(process_id, app, kernel_data)
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
            3 => {
                if self.current_app.is_some() {
                    return CommandReturn::failure(ErrorCode::BUSY);
                }

                let status = match arg1 {
                    0 => hil::MailboxStatus::Busy,
                    1 => hil::MailboxStatus::DataReady,
                    2 => hil::MailboxStatus::Complete,
                    3 => hil::MailboxStatus::Failure,
                    _ => return CommandReturn::failure(ErrorCode::INVAL),
                };

                let result = self
                    .apps
                    .enter(process_id, |_, _| {
                        match self.driver.set_command_status(status) {
                            Ok(_) => CommandReturn::success(),
                            Err(e) => {
                                println!("MCU_MBOX_CAPSULE: Error setting command status: {:?}", e);
                                CommandReturn::failure(e.into())
                            }
                        }
                    })
                    .map_err(|err| {
                        println!(
                            "MCU_MBOX_CAPSULE: Error accessing app to set command status: {:?}",
                            err
                        );
                        err.into()
                    });

                match result {
                    Ok(ret) => ret,
                    Err(err) => CommandReturn::failure(err),
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(process_id, |_, _| {})
    }
}
