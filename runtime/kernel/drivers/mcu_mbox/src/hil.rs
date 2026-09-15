// Licensed under the Apache-2.0 license

//! HIL Interface for MCU Mailbox Communication

use core::result::Result;
use kernel::ErrorCode;

/// MCU Mailbox Hardware Interface Layer (HIL).
///
/// This trait abstracts both sender and receiver flow.
/// For detailed protocol information, refer to the Caliptra Subsystem Integration Specification:
/// https://github.com/chipsalliance/caliptra-ss/blob/main/docs/CaliptraSSIntegrationSpecification.md#mcu-mailbox
pub trait Mailbox<'a> {
    /// Sends a command and associated data to the MCU mailbox (Sender mode).
    ///
    /// # Arguments
    ///
    /// * `command` - The command identifier to send.
    /// * `request_data` - Iterator yielding the request payload dwords to transmit.
    /// * `dlen` - Number of bytes to send from `request_data`.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err(ErrorCode)` if the operation fails.
    fn send_request(
        &self,
        command: u32,
        request_data: impl Iterator<Item = u32>,
        dlen: usize,
    ) -> Result<(), ErrorCode>;

    /// Writes a response to the MCU mailbox (Receiver mode).
    ///
    /// # Arguments
    ///
    /// * `response_data` - Iterator yielding the response payload dwords to write.
    /// * `dlen` - Number of bytes to write from `response_data`.
    /// * `status` - The status to set for the mailbox after writing the response.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err(ErrorCode)` if the operation fails.
    fn send_response(
        &self,
        response_data: impl Iterator<Item = u32>,
        dlen: usize,
    ) -> Result<(), ErrorCode>;

    /// Sets the command status of the MCU mailbox (Receiver mode).
    ///
    /// # Arguments
    /// * `status` - The status to set for the mailbox.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(ErrorCode)` if the operation fails.
    fn set_mbox_cmd_status(&self, status: MailboxStatus) -> Result<(), ErrorCode>;

    /// Returns the maximum size (in dword) of the MCU mailbox SRAM.
    fn max_mbox_sram_dw_size(&self) -> usize;

    /// Restores the receive buffer for the mailbox. This method is intended to be called by the client.
    ///
    /// # Arguments
    ///
    /// * `rx_buf` - The buffer to restore for receiving data.
    fn restore_rx_buffer(&self, rx_buf: &'static mut [u32]);

    /// Provides read-only access to the mailbox receive buffer without taking ownership of it.
    ///
    /// The receive buffer maps mailbox SRAM directly, and the sender is held off until the
    /// command status is set. A user-space client that cannot consume a request during `request_received`
    /// can therefore return the buffer immediately and re-read the payload later through this
    /// method, instead of buffering it elsewhere.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure invoked with the contents of the receive buffer.
    ///
    /// # Returns
    ///
    /// * `Some(R)` holding the closure result if the buffer is available.
    /// * `None` if the buffer is currently checked out by a client.
    fn map_rx_buffer<R>(&self, f: impl FnOnce(&[u32]) -> R) -> Option<R>;

    /// Enables the MCU mailbox driver instance.
    fn enable(&self);

    /// Disables the MCU mailbox driver instance.
    fn disable(&self);

    /// Registers a client to receive MCU mailbox event callbacks.
    ///
    /// # Arguments
    ///
    /// * `client` - Reference to an object implementing `MailboxClient`.
    fn set_client(&self, client: &'a dyn MailboxClient);
}

/// Represents the current status of the MCU mailbox.
#[derive(Debug, Copy, Clone)]
pub enum MailboxStatus {
    /// The command is still being processed.
    Busy,
    /// Data is available to be read.
    DataReady,
    /// The command completed successfully.
    Complete,
    /// The command failed.
    Failure,
}

/// Trait for clients that handle mailbox events and callbacks.
///
/// Implement this trait to receive asynchronous notifications for mailbox operations.
pub trait MailboxClient {
    /// Called when a mailbox request is received (Receiver mode).
    ///
    /// # Arguments
    ///
    /// * `command` - The command identifier of the received request.
    /// * `rx_buf` - Buffer containing the received data.
    /// * `dlen` - Number of valid bytes in `rx_buf`.
    fn request_received(&self, command: u32, rx_buf: &'static mut [u32], dlen: usize);

    /// Called when a response is received (Sender mode).
    ///
    /// # Arguments
    ///
    /// * `status` - The status of the mailbox after the response.
    /// * `rx_buf` - Buffer containing the response data.
    /// * `dlen` - Number of valid bytes in `rx_buf`.
    fn response_received(&self, status: MailboxStatus, rx_buf: &'static mut [u32], dlen: usize);

    /// Called when a send operation completes.
    ///
    /// # Arguments
    ///
    /// * `result` - Result of the send operation.
    fn send_done(&self, result: Result<(), ErrorCode>);
}
