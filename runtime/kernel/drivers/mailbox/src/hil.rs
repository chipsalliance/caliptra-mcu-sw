// Licensed under the Apache-2.0 license

//! HIL Interface for Caliptra Mailbox Communication

use core::result::Result;
use kernel::ErrorCode;

/// This trait supports both sending and receiving data, handling locks, and managing mailbox state transitions.
/// The full description of the mailbox interface can be found in the Caliptra Integration Specification:
/// https://github.com/chipsalliance/caliptra-rtl/blob/main/docs/CaliptraIntegrationSpecification.md#mailbox
pub trait Mailbox {
    /// Check if the mailbox lock is available.
    ///
    /// Returns:
    /// - `Ok(true)` if the mailbox is available and lock was acquired.
    /// - `Ok(false)` if the mailbox is currently locked by another device.
    /// - `Err(ErrorCode)` for any other error.
    fn acquire_lock(&self) -> Result<bool, ErrorCode>;

    /// Release the mailbox lock.
    ///
    /// Returns:
    /// - `Ok(())` if the lock was successfully released.
    /// - `Err(ErrorCode)` if there was an issue releasing the lock.
    fn release_lock(&self) -> Result<(), ErrorCode>;

    /// Write a command and data to the mailbox.
    ///
    /// # Arguments:
    /// - `command`: The command ID to write to the mailbox.
    /// - `data`: The data payload to send.
    ///
    /// Returns:
    /// - `Ok(())` if the data was successfully written.
    /// - `Err(ErrorCode)` if there was an issue with the operation.
    fn send_command(&self, command: u32, data: &[u8]) -> Result<(), ErrorCode>;

    /// Read data from the mailbox after the command execution.
    ///
    /// # Arguments:
    /// - `buffer`: A mutable buffer to store the response data.
    ///
    /// Returns:
    /// - `Ok(response_length)` where `response_length` is the number of bytes read.
    /// - `Err(ErrorCode)` if there was an issue reading the response.
    fn read_response(&self, buffer: &mut [u8]) -> Result<usize, ErrorCode>;

    /// Check the status of the mailbox after a command execution.
    ///
    /// Returns:
    /// - `Ok(MailboxStatus)` where `MailboxStatus` represents the current mailbox status.
    /// - `Err(ErrorCode)` if there was an issue checking the status.
    fn check_status(&self) -> Result<MailboxStatus, ErrorCode>;

    /// Handle incoming data when the mailbox data availability signal is asserted.
    ///
    /// # Arguments:
    /// - `buffer`: A mutable buffer to store the received data.
    ///
    /// Returns:
    /// - `Ok(length)` where `length` is the size of the received data.
    /// - `Err(ErrorCode)` if there was an issue processing the data.
    fn handle_incoming_data(&self, buffer: &mut [u8]) -> Result<usize, ErrorCode>;

    /// Populate the mailbox with a response if required.
    ///
    /// # Arguments:
    /// - `response_data`: The response data to populate in the mailbox.
    ///
    /// Returns:
    /// - `Ok(())` if the response was successfully populated.
    /// - `Err(ErrorCode)` if there was an issue writing the response.
    fn send_response(&self, response_data: &[u8]) -> Result<(), ErrorCode>;

    /// Set a client to receive callbacks on mailbox events.
    ///
    /// # Arguments:
    /// - `client`: A reference to an object implementing the `MailboxClient` trait.
    fn set_client(&self, client: &'static dyn MailboxClient);
}

/// Represents the current status of the mailbox.
#[derive(Debug, Copy, Clone)]
pub enum MailboxStatus {
    /// Command is still being processed.
    Busy,
    /// Data is ready to be read.
    DataReady,
    /// Command completed successfully.
    Complete,
    /// Command failed.
    Failure,
}

/// A client trait for handling mailbox callbacks.
///
/// This trait enables asynchronous notifications of mailbox events.
pub trait MailboxClient {
    /// Callback when the mailbox data is available for the receiver.
    ///
    /// # Arguments:
    /// - `command`: The command ID of the incoming mailbox data.
    /// - `length`: The size of the incoming data.
    fn data_available(&self, command: u32, length: usize);

    /// Callback when the sender's command completes.
    ///
    /// # Arguments:
    /// - `status`: The status of the command execution.
    fn command_complete(&self, status: MailboxStatus);

    /// Callback when an error occurs during mailbox operations.
    ///
    /// # Arguments:
    /// - `error`: An error code describing the failure.
    fn mailbox_error(&self, error: ErrorCode);
}
