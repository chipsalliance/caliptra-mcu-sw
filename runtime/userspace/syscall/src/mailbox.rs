// Licensed under the Apache-2.0 license

//! # Mailbox Interface
extern crate alloc;
use crate::DefaultSyscalls;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_api::mailbox::MailboxReqHeader;
use core::{hint::black_box, marker::PhantomData};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

// Global mutex to ensure that multiple tasks do not overwrite each other's upcall pointers.
static MAILBOX_MUTEX: Mutex<CriticalSectionRawMutex, u32> = Mutex::new(0);
const PAYLOAD_CHUNK_SIZE: usize = 256;

/// Mailbox interface user interface.
///
/// # Generics
/// - `S`: The syscall implementation.
pub struct Mailbox<S: Syscalls = DefaultSyscalls> {
    _syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Default for Mailbox<S> {
    fn default() -> Self {
        Self::new()
    }
}

// Populate the checksum for a mailbox request.
pub fn populate_checksum(cmd: u32, data: &mut [u8]) -> Result<(), ErrorCode> {
    // Calc checksum, use the size override if provided
    let checksum = caliptra_api::calc_checksum(cmd, data);

    if data.len() < size_of::<MailboxReqHeader>() {
        Err(ErrorCode::Invalid)?;
    }
    data[..size_of::<MailboxReqHeader>()].copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}

impl<S: Syscalls> Mailbox<S> {
    pub fn new() -> Self {
        Self {
            _syscall: PhantomData,
            driver_num: MAILBOX_DRIVER_NUM,
        }
    }

    // Populate the checksum for a mailbox request.
    pub fn populate_checksum(&self, cmd: u32, data: &mut [u8]) -> Result<(), ErrorCode> {
        populate_checksum(cmd, data)
    }

    /// Executes a mailbox command and returns the response.
    ///
    /// This method sends a mailbox command to the kernel, then waits
    /// asynchronously for the command to complete. The response buffer is filled with
    /// the result from the kernel.
    ///
    /// # Arguments
    /// - `command`: The mailbox command ID to execute.
    /// - `input_data`: A read-only buffer containing the mailbox command parameters.
    /// - `response_buffer`: A writable buffer to store the response data.
    ///
    /// # Returns
    /// - `Ok(usize)` on success, containing the number of bytes written to the response buffer.
    /// - `Err(ErrorCode)` if the command fails.
    pub async fn execute(
        &self,
        command: u32,
        input_data: &[u8],
        response_buffer: &mut [u8],
    ) -> Result<usize, MailboxError> {
        let result = {
            // lock the global mailbox mutex to ensure exclusive access
            let mutex = MAILBOX_MUTEX.lock().await;

            // Subscribe to the asynchronous notification for when the command is processed
            let result = share::scope::<(), _, _>(|_handle| {
                let mut sub = TockSubscribe::subscribe_allow_ro_rw::<S, DefaultConfig>(
                    self.driver_num,
                    mailbox_subscribe::COMMAND_DONE,
                    mailbox_ro_buffer::INPUT,
                    input_data,
                    mailbox_rw_buffer::RESPONSE,
                    response_buffer,
                );

                // Issue the command to the kernel
                match S::command(self.driver_num, mailbox_cmd::EXECUTE_COMMAND, command, 0)
                    .to_result::<(), ErrorCode>()
                {
                    Ok(()) => Ok(TockSubscribe::subscribe_finish(sub)),
                    Err(err) => {
                        S::unallow_ro(self.driver_num, mailbox_ro_buffer::INPUT);
                        S::unallow_rw(self.driver_num, mailbox_rw_buffer::RESPONSE);
                        // If command returned error immediately, cancel the future
                        sub.cancel();
                        Err(MailboxError::ErrorCode(err))
                    }
                }
            })?
            .await;

            black_box(*mutex); // Ensure the mutex is not optimized away

            result
        };

        match result {
            Ok((bytes, error_code, _)) => {
                if error_code != 0 {
                    Err(MailboxError::MailboxError(error_code))
                } else {
                    Ok(bytes as usize)
                }
            }
            Err(err) => Err(MailboxError::ErrorCode(err)),
        }
    }

    pub async fn execute_with_payload_stream(
        &self,
        command: u32,
        header: Option<&[u8]>,
        payload: &mut dyn PayloadStream,
        response_buffer: &mut [u8],
    ) -> Result<usize, MailboxError> {
        let mutex = MAILBOX_MUTEX.lock().await;

        let request_len = payload.size() + header.map_or(0, |h| h.len());

        // Send the command to initiate mailbox request
        S::command(
            self.driver_num,
            mailbox_cmd::START_CHUNKED_REQUEST,
            command,
            request_len as u32,
        )
        .to_result::<(), ErrorCode>()
        .map_err(MailboxError::ErrorCode)?;

        // Send the header if provided
        let mut buffer = [0u8; PAYLOAD_CHUNK_SIZE];
        if let Some(header) = header {
            // If a header is provided, write it to the buffer first
            buffer[..header.len()].copy_from_slice(header);
            self.send_chunk(buffer[..header.len()].as_ref()).await?;
        }

        // Send the payload in chunks
        loop {
            // Read a chunk of data from the payload stream
            let sz = payload
                .read(&mut buffer)
                .await
                .map_err(MailboxError::ErrorCode)?;
            if sz == 0 {
                break; // No more data to read
            }
            self.send_chunk(buffer[..sz].as_ref()).await?;
        }

        // Execute the command
        let result = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                mailbox_subscribe::COMMAND_DONE,
                mailbox_rw_buffer::RESPONSE,
                response_buffer,
            );

            // Issue the command to the kernel
            match S::command(
                self.driver_num,
                mailbox_cmd::EXECUTE_CHUNKED_REQUEST,
                command,
                0,
            )
            .to_result::<(), ErrorCode>()
            {
                Ok(()) => Ok(TockSubscribe::subscribe_finish(sub)),
                Err(err) => {
                    S::unallow_rw(self.driver_num, mailbox_rw_buffer::RESPONSE);
                    sub.cancel();
                    Err(MailboxError::ErrorCode(err))
                }
            }
        })?
        .await;
        black_box(*mutex); // Ensure the mutex is not optimized away
        match result {
            Ok((bytes, error_code, _)) => {
                if error_code != 0 {
                    Err(MailboxError::MailboxError(error_code))
                } else {
                    Ok(bytes as usize)
                }
            }
            Err(err) => Err(MailboxError::ErrorCode(err)),
        }
    }

    async fn send_chunk(&self, buffer: &[u8]) -> Result<(u32, u32, u32), MailboxError> {
        share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                mailbox_subscribe::COMMAND_DONE,
                mailbox_ro_buffer::INPUT,
                buffer,
            );

            // Issue the command to the kernel
            match S::command(self.driver_num, mailbox_cmd::NEXT_PAYLOAD_CHUNK, 0, 0)
                .to_result::<(), ErrorCode>()
            {
                Ok(()) => Ok(TockSubscribe::subscribe_finish(sub)),
                Err(err) => {
                    S::unallow_ro(self.driver_num, mailbox_ro_buffer::INPUT);
                    sub.cancel();
                    Err(MailboxError::ErrorCode(err))
                }
            }
        })?
        .await
        .map_err(MailboxError::ErrorCode)
    }
}
#[async_trait(?Send)]
pub trait PayloadStream {
    /// Returns the size of the payload in bytes.
    fn size(&self) -> usize;

    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ErrorCode>;
}

// -----------------------------------------------------------------------------
// Command IDs and Mailbox-specific constants
// -----------------------------------------------------------------------------

// Driver number for the Mailbox interface
pub const MAILBOX_DRIVER_NUM: u32 = 0x8000_0009;

/// Command IDs for mailbox operations.
mod mailbox_cmd {
    pub const _STATUS: u32 = 0;
    /// Execute a command with input and response buffers.
    pub const EXECUTE_COMMAND: u32 = 1;
    pub const START_CHUNKED_REQUEST: u32 = 2;
    pub const NEXT_PAYLOAD_CHUNK: u32 = 3;
    pub const EXECUTE_CHUNKED_REQUEST: u32 = 4;
}

/// Buffer IDs for mailbox read operations.
mod mailbox_ro_buffer {
    /// Buffer ID for the input buffer (read-only).
    pub const INPUT: u32 = 0;
}

/// Buffer IDs for mailbox read-write operations.
mod mailbox_rw_buffer {
    /// Buffer ID for the response buffer (read-write).
    pub const RESPONSE: u32 = 0;
}

/// Subscription IDs for asynchronous mailbox events.
mod mailbox_subscribe {
    /// Subscription ID for the `COMMAND_DONE` event.
    pub const COMMAND_DONE: u32 = 0;
}

#[derive(Debug, PartialEq)]
pub enum MailboxError {
    ErrorCode(ErrorCode),
    MailboxError(u32),
}
