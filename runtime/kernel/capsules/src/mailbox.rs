// Licensed under the Apache-2.0 license

//! This provides the mailbox capsule that calls the underlying mailbox driver to
//! communicate with Caliptra.

use crate::dma::hil::{Dma, DmaRoute, DmaStatus};
use caliptra_api::CaliptraApiError;
use core::cell::Cell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::hil::time::{Alarm, AlarmClient};
use kernel::processbuffer::{
    ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer, WriteableProcessSlice,
};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{debug, ErrorCode, ProcessId};
use romtime::CaliptraSoC;

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
    resp_min_size: Cell<usize>,
    resp_size: Cell<usize>,
    /// AXI address of the staging SRAM
    staging_sram_axi_addr: Option<u64>,
    current_request_offset: Cell<usize>,
    current_cmd: Cell<u32>,
    // DMA peripheral for data transfers
    dma_driver: &'static dyn Dma,
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
        staging_sram_axi_addr: Option<u64>,
        dma_driver: &'static dyn Dma,
    ) -> Mailbox<'a, A> {
        Mailbox {
            alarm,
            driver: TakeCell::new(driver),
            apps: grant,
            current_app: OptionalCell::empty(),
            resp_min_size: Cell::new(0),
            resp_size: Cell::new(0),
            staging_sram_axi_addr,
            current_request_offset: Cell::new(0),
            current_cmd: Cell::new(0),
            dma_driver,
        }
    }

    // Check if any command is pending. If not, this command is executed.
    // If so, this command is queued and will be run when the pending
    // command is completed.
    fn enqueue_command(&self, command: u32, processid: ProcessId) -> Result<(), ErrorCode> {
        // Check if we're already executing a mailbox command.
        if self.current_app.is_some() {
            return Err(ErrorCode::BUSY);
        }
        self.current_cmd.set(command);
        self.apps.enter(processid, |_app, kernel_data| {
            // copy the request so we can write async
            kernel_data
                .get_readonly_processbuffer(ro_allow::REQUEST)
                .map_err(|err| {
                    debug!("Error getting process buffer: {:?}", err);
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
                            debug!("Error getting application buffer: {:?}", err);
                            ErrorCode::FAIL
                        })?
                })
        })?
    }

    fn copy_app_buffer_to_staging_sram(
        &self,
        app_buffer: &ReadableProcessSlice,
        offset: usize,
    ) -> Result<(), ErrorCode> {
        const CHUNK_SIZE: usize = 256;
        const MAX_DMA_POLL_TRIES: usize = 10000;
        let buffer_len = app_buffer.len();
        let mut bytes_written = 0;

        // Process in CHUNK_SIZE byte chunks
        while bytes_written < buffer_len {
            let chunk_len = core::cmp::min(CHUNK_SIZE, buffer_len - bytes_written);
            let mut chunk_buf = [0u8; CHUNK_SIZE];

            if let Some(chunk) = app_buffer.get(bytes_written..bytes_written + chunk_len) {
                chunk.copy_to_slice(&mut chunk_buf[..chunk_len]);

                // Configure and execute DMA transfer for this chunk
                let src_addr = chunk_buf.as_ptr() as u64;
                let dest_addr =
                    self.staging_sram_axi_addr.unwrap() + (offset + bytes_written) as u64;
                self.dma_driver.configure_transfer(
                    chunk_len,
                    chunk_len,
                    Some(src_addr),
                    Some(dest_addr),
                )?;

                // Start the DMA transfer for this chunk
                self.dma_driver
                    .start_transfer(DmaRoute::AxiToAxi, DmaRoute::AxiToAxi, false)
                    .map_err(|_| ErrorCode::FAIL)?;

                // Poll for completion of this chunk
                let mut completed = false;
                for _ in 0..MAX_DMA_POLL_TRIES {
                    match self.dma_driver.poll_status() {
                        Ok(DmaStatus::TxnDone) => {
                            completed = true;
                            break;
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            debug!("DMA transfer error: {:?}", e);
                            return Err(ErrorCode::FAIL);
                        }
                    }
                }
                if !completed {
                    debug!("DMA transfer timed out");
                    return Err(ErrorCode::FAIL);
                }

                bytes_written += chunk_len;
            } else {
                debug!(
                    "Failed to get chunk from app_buffer at offset {}",
                    bytes_written
                );
                return Err(ErrorCode::FAIL);
            }
        }

        Ok(())
    }

    fn start_request(
        &self,
        processid: ProcessId,
        driver: &mut CaliptraSoC,
        command: u32,
        app_buffer: &ReadableProcessSlice,
    ) -> Result<(), ErrorCode> {
        self.current_app.set(processid);

        if let Some(staging_axi_addr) = self.staging_sram_axi_addr {
            // Copy payload to staging SRAM
            self.copy_app_buffer_to_staging_sram(app_buffer, 0)?;

            match driver.execute_ext_mailbox_req(command, app_buffer.len(), staging_axi_addr) {
                Ok(_) => {
                    self.schedule_alarm();
                    Ok(())
                }
                Err(err) => {
                    debug!("Error starting mailbox command: {:?}", err);
                    Err(ErrorCode::FAIL)
                }
            }
        } else {
            // Copy payload to mailbox directly
            match driver.start_mailbox_req(
                command,
                app_buffer.len(),
                app_buffer.chunks(4).map(|chunk| {
                    let mut dest = [0u8; 4];
                    chunk.copy_to_slice(&mut dest);
                    u32::from_le_bytes(dest)
                }),
            ) {
                Ok(_) => {
                    self.schedule_alarm();
                    Ok(())
                }
                Err(err) => {
                    debug!("Error starting mailbox command: {:?}", err);
                    Err(ErrorCode::FAIL)
                }
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
        if self.current_app.is_some() {
            return Err(ErrorCode::BUSY);
        }
        self.current_app.set(processid);
        self.current_cmd.set(command);
        if self.staging_sram_axi_addr.is_none() {
            // If not using staging SRAM, then the mailbox command can be initiated directly.
            let _ = self
                .driver
                .map(|driver| {
                    driver
                        .initiate_request(command, payload_size)
                        .map_err(|_| ErrorCode::FAIL)
                })
                .ok_or(ErrorCode::RESERVE)?;
        }
        Ok(())
    }

    fn send_next_chunk(&self, processid: ProcessId) -> Result<(), ErrorCode> {
        // Check if we're already executing a mailbox command.
        if self.current_app.is_none() {
            return Err(ErrorCode::CANCEL);
        }
        self.apps.enter(processid, |_app, kernel_data| {
            // copy the request so we can write async
            kernel_data
                .get_readonly_processbuffer(ro_allow::REQUEST)
                .map_err(|err| {
                    debug!("Error getting process buffer: {:?}", err);
                    ErrorCode::FAIL
                })
                .and_then(|ro_buffer| {
                    ro_buffer
                        .enter(|app_buffer| self.write_chunk(app_buffer))
                        .map_err(|err| {
                            debug!("Error getting application buffer: {:?}", err);
                            ErrorCode::FAIL
                        })?
                })?;
            kernel_data
                .schedule_upcall(upcall::COMMAND_DONE, (0, 0, 0))
                .map_err(|err| {
                    debug!("Error scheduling upcall: {:?}", err);
                    ErrorCode::FAIL
                })
        })?
    }

    fn write_chunk(&self, app_buffer: &ReadableProcessSlice) -> Result<(), ErrorCode> {
        if self.staging_sram_axi_addr.is_none() {
            // Copy payload directly to mailbox
            let _ = self
                .driver
                .map(|driver| {
                    for chunk in app_buffer.chunks(4) {
                        if chunk.len() == 4 {
                            let mut buf = [0u8; 4];
                            chunk.copy_to_slice(&mut buf);
                            let data = u32::from_le_bytes(buf);
                            driver.write_data(data).map_err(|_| ErrorCode::FAIL)?;
                        } else {
                            // If the last chunk is not 4 bytes, we can't write it to the mailbox
                            debug!("Error: Incomplete data chunk in mailbox request");
                            return Err(ErrorCode::FAIL);
                        }
                    }
                    Ok(())
                })
                .ok_or(ErrorCode::RESERVE)?;
        } else {
            // Copy payload to staging SRAM
            let offset = self.current_request_offset.get();
            let buffer_len = app_buffer.len();
            self.copy_app_buffer_to_staging_sram(app_buffer, offset)?;
            self.current_request_offset.set(offset + buffer_len);
        }

        Ok(())
    }

    fn execute(&self) -> Result<(), ErrorCode> {
        // Check if we're already executing a mailbox command.
        if self.current_app.is_none() {
            return Err(ErrorCode::CANCEL);
        }
        if let Some(staging_axi_addr) = self.staging_sram_axi_addr {
            // If using staging SRAM, execute the command with staging address
            self.driver
                .map(|driver| {
                    match driver.execute_ext_mailbox_req(
                        self.current_cmd.take(),
                        self.current_request_offset.take(),
                        staging_axi_addr,
                    ) {
                        Ok(()) => {
                            self.schedule_alarm();
                            Ok(())
                        }
                        Err(_) => Err(ErrorCode::FAIL),
                    }
                })
                .unwrap_or(Err(ErrorCode::FAIL))?;
        } else {
            self.driver
                .map(|driver| match driver.execute_command() {
                    Ok(()) => {
                        self.schedule_alarm();
                        Ok(())
                    }
                    Err(_) => Err(ErrorCode::FAIL),
                })
                .unwrap_or(Err(ErrorCode::FAIL))?;
        }
        Ok(())
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
                debug!("Error copying from mailbox: {:?}", err);
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
                            debug!("Error accessing writable buffer {:?}", err);
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
                                debug!("Error scheduling upcall: {:?}", err);
                            }
                        }
                        Ok(Ok(len)) => {
                            if let Err(err) =
                                kernel_data.schedule_upcall(upcall::COMMAND_DONE, (len, 0, 0))
                            {
                                debug!("Error scheduling upcall: {:?}", err);
                            }
                        }
                    }
                }
            });
            if let Err(err) = enter_result {
                debug!("Error entering app: {:?}", err);
            }
        }
    }

    fn schedule_alarm(&self) {
        let now = self.alarm.now();
        let dt = A::Ticks::from(10000);
        self.alarm.set_alarm(now, dt);
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for Mailbox<'a, A> {
    fn alarm(&self) {
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
            self.current_app.take(); // clear the current app so another app can use the mailbox
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
                let res = self.execute();
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
