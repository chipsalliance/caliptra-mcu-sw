// Licensed under the Apache-2.0 license

use caliptra_mcu_mbox_comm::hil;
use caliptra_mcu_romtime::println;
use core::cell::Cell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
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

/// Metadata for a request whose payload is still sitting in the retained driver buffer.
///
/// The payload itself is NOT copied here. It stays in the `&'static mut [u32]` the
/// low-level driver lent us, which this capsule holds in `held_rx` until the owning app
/// collects it. Keeping the payload out of the grant is the entire point: it used to be a
/// `[u32; 2304]` inside `App`, which made the per-process grant 9268 B and meant every
/// process paid ~9 KiB of its RAM for a buffer that already existed once in the driver.
#[derive(Copy, Clone)]
struct HeldRequest {
    command: u32,
    dlen: usize,
}

#[derive(Default)]
pub struct App {
    waiting_rx: Cell<bool>, // Indicates if a request is waiting to be received
    pending_tx: Cell<bool>, // Indicates if a response is pending to be sent
    has_pending: Cell<bool>, // A retained request is addressed to this app
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
    /// The driver's rx buffer, retained while a request awaits collection.
    held_rx: TakeCell<'static, [u32]>,
    /// Metadata for the request held in `held_rx`.
    held: OptionalCell<HeldRequest>,
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
            held_rx: TakeCell::empty(),
            held: OptionalCell::empty(),
        }
    }

    /// Hand the retained buffer back to the driver and forget the held request.
    ///
    /// MUST be called before the driver can return to `RxWait`. The low-level driver
    /// `panic!`s if a request arrives while it is in `RxWait` with no rx buffer
    /// (`handle_incoming_request`, "No data buffer available for incoming request"), and
    /// `set_mbox_cmd_status` is what puts it back into `RxWait`. Retaining the buffer is
    /// only safe because delivery leaves the driver in `RespFinishPending`, where
    /// `handle_incoming_request` returns early -- so every path that can reach
    /// `set_mbox_cmd_status` has to come through here first.
    fn release_held(&self) {
        if let Some(buf) = self.held_rx.take() {
            self.driver.restore_rx_buffer(buf);
        }
        self.held.clear();
        self.apps.each(|_, app, _| app.has_pending.set(false));
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

    fn deliver_message(
        &self,
        app: &mut App,
        kernel_data: &GrantKernelData<'_>,
    ) -> Result<(), ErrorCode> {
        let Some(request) = self.held.get() else {
            return Err(ErrorCode::FAIL);
        };
        if !app.has_pending.get() {
            return Err(ErrorCode::FAIL);
        }

        if app.waiting_rx.get() {
            app.waiting_rx.set(false);
        }

        let command = request.command;
        let dlen = request.dlen;
        let dw_len = dlen.div_ceil(4);

        // Copy straight out of the retained driver buffer. `map_or` rather than an
        // unwrap: if the buffer is somehow gone the request cannot be served, and this
        // capsule must not panic on a path the SoC can drive.
        let result = self.held_rx.map_or(Err(ErrorCode::FAIL), |held_buf| {
            kernel_data
                .get_readwrite_processbuffer(rw_allow::REQUEST)
                .map_err(|_| ErrorCode::INVAL)
                .and_then(|rw_buf| {
                    rw_buf
                        .mut_enter(|buf| -> Result<usize, ErrorCode> {
                            let copy_len_dw = core::cmp::min(buf.len() / 4, dw_len);
                            for i in 0..copy_len_dw {
                                let start = i * 4;
                                let end = start + 4;
                                let bytes = held_buf[i].to_le_bytes();
                                buf[start..end].copy_from_slice(&bytes);
                            }
                            Ok(core::cmp::min(copy_len_dw * 4, dlen))
                        })
                        .map_err(|_| ErrorCode::FAIL)
                })
        });

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
                    return Err(ErrorCode::FAIL);
                }
            }
            Ok(Err(err)) => {
                capsule_debug!(
                    "MCU_MBOX",
                    "deliver_message error copying data to app buffer: {}",
                    err as u32
                );
                return Err(err);
            }
            Err(err) => {
                capsule_debug!(
                    "MCU_MBOX",
                    "deliver_message error while accessing app buffer: {}",
                    err as u32
                );
                return Err(err);
            }
        }

        // Delivered: this app no longer has a claim on the retained buffer. Give the
        // buffer back as soon as nobody else does, so the driver is never left in
        // `RxWait` without one.
        app.has_pending.set(false);
        if !self.any_pending() {
            self.release_held();
        }

        Ok(())
    }

    /// True while any app still has a claim on the retained request.
    fn any_pending(&self) -> bool {
        let mut pending = false;
        self.apps.each(|_, app, _| {
            if app.has_pending.get() {
                pending = true;
            }
        });
        pending
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

        // A request that arrives while an app is not waiting used to be COPIED into that
        // app's grant. Instead, mark the app and retain the driver's buffer; the payload
        // is collected from it on the app's next RECEIVE. Retention is safe here because
        // the driver moves to `RespFinishPending` immediately after this callback returns,
        // and `handle_incoming_request` early-returns unless the state is `RxWait` -- so no
        // further request can reach the "no data buffer" panic while we hold it.
        let mut retain = false;
        self.apps.each(|_, app, kernel_data| {
            if app.waiting_rx.get() {
                app.waiting_rx.set(false);
            } else {
                app.has_pending.set(true);
                retain = true;
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
                    kernel_data
                        .schedule_upcall(upcall::REQUEST_RECEIVED, (command as usize, len, 0))
                        .ok();
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

        if retain {
            self.held.set(HeldRequest { command, dlen });
            self.held_rx.replace(rx_buf);
        } else {
            // Delivered to every waiting app; the payload has been copied out.
            self.driver.restore_rx_buffer(rx_buf);
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
                    // If a request is being held for this app, deliver it immediately
                    if app.has_pending.get() {
                        self.deliver_message(app, kernel_data)?;
                    }
                    Ok(())
                });

                // Report the inner ErrorCode instead of collapsing it. `Ok(_)` swallowed
                // `Ok(Err(BUSY))` and every `deliver_message` failure, reporting them to
                // userspace as SUCCESS, so a grant-allocation failure was the only fault
                // this syscall could express. Arm 3 below already does this correctly.
                match res {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(e)) => CommandReturn::failure(e),
                    Err(err) => CommandReturn::failure(err.into()),
                }
            }
            // Send response message
            2 => {
                if self.current_app.is_some() {
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

                // MUST precede set_mbox_cmd_status, which returns the driver to `RxWait`.
                // If we were still holding the rx buffer at that point, the next incoming
                // request would hit `handle_incoming_request`'s "No data buffer available"
                // panic. This is reachable in practice: the userspace responder calls
                // finalize_response (this arm) on its receive-error path, without ever
                // having collected the held request.
                self.release_held();

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
