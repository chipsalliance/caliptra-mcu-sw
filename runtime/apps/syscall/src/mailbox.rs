// Licensed under the Apache-2.0 license

//! # Mailbox Interface

use core::marker::PhantomData;
use libtock_platform::{share, AllowRo, AllowRw, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

/// Mailbox interface user interface.
///
/// # Generics
/// - `S`: The syscall implementation.
pub struct Mailbox<S: Syscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Default for Mailbox<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> Mailbox<S> {
    pub fn new() -> Self {
        Self {
            syscall: PhantomData,
            driver_num: MAILBOX_DRIVER_NUM,
        }
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
    ) -> Result<usize, ErrorCode> {
        // Subscribe to the asynchronous notification for when the command is processed
        let async_command =
            TockSubscribe::subscribe::<S>(self.driver_num, mailbox_subscribe::COMMAND_DONE);

        share::scope::<
            (
                AllowRo<_, MAILBOX_DRIVER_NUM, { mailbox_ro_buffer::INPUT }>,
                AllowRw<_, MAILBOX_DRIVER_NUM, { mailbox_rw_buffer::RESPONSE }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_ro, allow_rw) = handle.split();
            S::allow_ro::<DefaultConfig, MAILBOX_DRIVER_NUM, { mailbox_ro_buffer::INPUT }>(
                allow_ro, input_data,
            )?;
            S::allow_rw::<DefaultConfig, MAILBOX_DRIVER_NUM, { mailbox_rw_buffer::RESPONSE }>(
                allow_rw,
                response_buffer,
            )?;
            // Issue the command to the kernel
            S::command(self.driver_num, mailbox_cmd::EXECUTE_COMMAND, command, 0)
                .to_result::<(), ErrorCode>()?;
            Ok(())
        })?;

        async_command.await.map(|res| res.0 as usize)
    }
}

// -----------------------------------------------------------------------------
// Command IDs and Mailbox-specific constants
// -----------------------------------------------------------------------------

// Driver number for the Mailbox interface
pub const MAILBOX_DRIVER_NUM: u32 = 0x8000_0009;

/// Command IDs for mailbox operations.
mod mailbox_cmd {
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
