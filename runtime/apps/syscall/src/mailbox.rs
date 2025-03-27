// Licensed under the Apache-2.0 license

//! # Mailbox Interface

use caliptra_api::mailbox::MailboxReqHeader;
use core::marker::PhantomData;
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

/// Mailbox interface user interface.
///
/// # Generics
/// - `S`: The syscall implementation.
pub struct Mailbox<S: Syscalls> {
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
        // Subscribe to the asynchronous notification for when the command is processed
        let result: Result<(u32, u32, u32), ErrorCode> = share::scope::<(), _, _>(|_handle| {
            let sub = TockSubscribe::subscribe_allow_ro_rw::<S, DefaultConfig>(
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
                Ok(()) => Ok(sub),
                Err(err) => {
                    S::unallow_ro(self.driver_num, mailbox_ro_buffer::INPUT);
                    S::unallow_rw(self.driver_num, mailbox_rw_buffer::RESPONSE);
                    Err(MailboxError::ErrorCode(err))
                }
            }
        })?
        .await;

        S::unallow_ro(self.driver_num, mailbox_ro_buffer::INPUT);
        S::unallow_rw(self.driver_num, mailbox_rw_buffer::RESPONSE);

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

#[derive(Debug)]
pub enum MailboxError {
    ErrorCode(ErrorCode),
    MailboxError(u32),
}
