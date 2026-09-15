// Licensed under the Apache-2.0 license

use caliptra_mcu_mbox_comm::hil;
use caliptra_mcu_romtime::println;
use core::cell::Cell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::OptionalCell;
use kernel::{ErrorCode, ProcessId};

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

/// Metadata of a request that arrived while no application was listening.
///
/// The payload itself is left in mailbox SRAM, so only the notification needs
/// to be retained here.
#[derive(Copy, Clone)]
struct StagedRequest {
    command: u32,
    dlen: usize,
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
    staged_request: OptionalCell<StagedRequest>,
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
            staged_request: OptionalCell::empty(),
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
            .map_err(|_e| {
                capsule_debug!(
                    "MCU_MBOX",
                    "Error getting ReadOnlyProcessBuffer buffer: {}",
                    _e as u32
                );
                ErrorCode::INVAL
            })
            .and_then(|tx_buf| {
                tx_buf
                    .enter(|app_buf| self.start_transmit(app_buf))
                    .map_err(|_e| {
                        capsule_debug!(
                            "MCU_MBOX",
                            "Error getting application tx buffer: {}",
                            _e as u32
                        );
                        ErrorCode::FAIL
                    })
            })?;

        app.pending_tx.set(true);
        Ok(())
    }

    fn stage_request(&self, command: u32, dlen: usize) {
        // Print warning if replacing an old staged request
        if self.staged_request.is_some() {
            capsule_debug!(
                "MCU_MBOX",
                "Warning - replacing old staged request with new one"
            );
        }
        // Always replace the old staged request with the new one
        self.staged_request.set(StagedRequest { command, dlen });
    }

    fn deliver_message(
        &self,
        app: &mut App,
        kernel_data: &GrantKernelData<'_>,
    ) -> Result<(), ErrorCode> {
        let staged = match self.staged_request.take() {
            Some(staged) => staged,
            None => return Err(ErrorCode::FAIL),
        };

        if app.waiting_rx.get() {
            app.waiting_rx.set(false);
        }

        let command = staged.command;
        let dlen = staged.dlen;
        let dw_len = dlen.div_ceil(4);

        // The payload was never copied out of mailbox SRAM, so read it back from there.
        let result = self
            .driver
            .map_rx_buffer(|rx_buf| {
                if dw_len > rx_buf.len() {
                    return Err(ErrorCode::SIZE);
                }
                kernel_data
                    .get_readwrite_processbuffer(rw_allow::REQUEST)
                    .map_err(|_| ErrorCode::INVAL)
                    .and_then(|rw_buf| {
                        rw_buf
                            .mut_enter(|buf| -> Result<usize, ErrorCode> {
                                let copy_len_dw = core::cmp::min(buf.len() / 4, dw_len);
                                for (i, &data) in rx_buf.iter().enumerate().take(copy_len_dw) {
                                    let start = i * 4;
                                    let end = start + 4;
                                    let bytes = data.to_le_bytes();
                                    buf[start..end].copy_from_slice(&bytes);
                                }
                                Ok(core::cmp::min(copy_len_dw * 4, dlen))
                            })
                            .map_err(|_| ErrorCode::FAIL)
                    })
            })
            .unwrap_or(Err(ErrorCode::BUSY));

        match result {
            Ok(Ok(len)) => {
                if let Err(_e) = kernel_data
                    .schedule_upcall(upcall::REQUEST_RECEIVED, (command as usize, len, 0))
                {
                    capsule_debug!(
                        "MCU_MBOX",
                        "deliver_message error scheduling upcall: {}",
                        _e as u32
                    );
                    self.staged_request.set(staged);
                    return Err(ErrorCode::FAIL);
                }
            }
            Ok(Err(err)) => {
                capsule_debug!(
                    "MCU_MBOX",
                    "deliver_message error copying data to app buffer: {}",
                    err as u32
                );
                self.staged_request.set(staged);
                return Err(err);
            }
            Err(err) => {
                capsule_debug!(
                    "MCU_MBOX",
                    "deliver_message error while accessing app buffer: {}",
                    err as u32
                );
                self.staged_request.set(staged);
                return Err(err);
            }
        }

        Ok(())
    }
}

impl<'a, T: hil::Mailbox<'a>> hil::MailboxClient for McuMboxDriver<'a, T> {
    fn request_received(&self, command: u32, rx_buf: &'static mut [u32], dlen: usize) {
        let dw_len = dlen.div_ceil(4);
        if dw_len > rx_buf.len() {
            capsule_debug!(
                "MCU_MBOX",
                "Received request with invalid length {}",
                dw_len
            );
            self.driver.restore_rx_buffer(rx_buf);
            return;
        }

        let mut delivered = false;

        self.apps.each(|_, app, kernel_data| {
            if app.waiting_rx.get() {
                app.waiting_rx.set(false);
            } else {
                return;
            }

            let process_result: Result<Result<usize, ErrorCode>, ErrorCode> =
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
                                capsule_error!(
                                    "MCU_MBOX",
                                    "Error entering WriteableProcessBuffer buffer: 0x{:08x}",
                                    e as u32
                                );
                                e.into()
                            })
                    }
                    Err(_err) => {
                        capsule_debug!(
                            "MCU_MBOX",
                            "Error getting WriteableProcessBuffer buffer: {}",
                            _err as u32
                        );
                        Err(ErrorCode::INVAL)
                    }
                };

            match process_result {
                Ok(Ok(len)) => {
                    if kernel_data
                        .schedule_upcall(upcall::REQUEST_RECEIVED, (command as usize, len, 0))
                        .is_ok()
                    {
                        delivered = true;
                    }
                }
                Ok(Err(err)) => {
                    capsule_error!(
                        "MCU_MBOX",
                        "Error copying data to app buffer: 0x{:08x}",
                        err as u32
                    );
                }
                Err(err) => {
                    capsule_error!(
                        "MCU_MBOX",
                        "Error while accessing app buffer: 0x{:08x}",
                        err as u32
                    );
                }
            }
        });
        // Restore driver rx buffer
        self.driver.restore_rx_buffer(rx_buf);

        // No application consumed the request. The payload stays in mailbox SRAM and the
        // sender stays blocked until the command status is set, so only record the
        // notification.
        if !delivered {
            self.stage_request(command, dlen);
        }
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
                // Receive request message
                let res = self.apps.enter(process_id, |app, kernel_data| {
                    if app.waiting_rx.get() {
                        return Err(ErrorCode::BUSY);
                    }
                    app.waiting_rx.set(true);
                    // If there's a staged request, deliver it immediately
                    if self.staged_request.is_some() {
                        self.deliver_message(app, kernel_data)?;
                    }
                    Ok(())
                });

                match res {
                    Ok(_) => CommandReturn::success(),
                    Err(err) => CommandReturn::failure(err.into()),
                }
            }
            // Send response message
            2 => {
                if self.current_app.is_some() {
                    return CommandReturn::failure(ErrorCode::BUSY);
                }

                // The staged request still occupies mailbox SRAM. Sending a response now
                // would overwrite it before the application has read it.
                if self.staged_request.is_some() {
                    return CommandReturn::failure(ErrorCode::BUSY);
                }

                let result = self
                    .apps
                    .enter(process_id, |app, kernel_data| {
                        if app.pending_tx.get() {
                            return Err(ErrorCode::BUSY);
                        }
                        self.send_app_response(process_id, app, kernel_data)
                    })
                    .map_err(|err| err.into());

                match result {
                    Ok(_) => CommandReturn::success(),
                    Err(err) => CommandReturn::failure(err),
                }
            }
            // Finish response
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

                self.current_app.set(process_id);

                // The transaction is over, so any request still staged is stale.
                self.staged_request.clear();

                let result = self
                    .apps
                    .enter(process_id, |_, _| self.driver.set_mbox_cmd_status(status))
                    .map_err(|err| err.into());

                self.current_app.take();

                match result {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) | Err(e) => CommandReturn::failure(e),
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(process_id, |_, _| {})
    }
}
