/*++

Licensed under the Apache-2.0 license.

File Name:

    network_mbox.rs

Abstract:

    Hardware Interface Layer trait for Network Mailbox peripherals.

--*/

/// Represents the status of a network mailbox command.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NetworkMboxStatus {
    /// The command is still being processed.
    CmdBusy,
    /// Requested data is ready in the network mailbox.
    DataReady,
    /// Requested command is complete.
    CmdComplete,
    /// The requested command experienced a failure.
    CmdFailure,
}

/// Represents the target status of a network mailbox operation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NetworkMboxTargetStatus {
    /// The status of the target's processing.
    pub status: NetworkMboxStatus,
    /// Indicates the target user is done and the status is valid.
    pub done: bool,
}

/// Hardware status flags for the network mailbox.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NetworkMboxHwStatus {
    /// A correctable ECC single-bit error was detected and corrected.
    pub ecc_single_error: bool,
    /// An uncorrectable ECC double-bit error was detected.
    pub ecc_double_error: bool,
}

/// Errors specific to network mailbox operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NetworkMboxError {
    /// The mailbox is locked by another agent.
    Locked,
    /// The mailbox is not locked (operation requires lock).
    NotLocked,
    /// The data length exceeds the SRAM capacity.
    DataTooLarge,
    /// An invalid argument was provided.
    InvalidArgument,
    /// A hardware error occurred (e.g., ECC double-bit error).
    HardwareError,
    /// The operation failed.
    Failed,
    /// The operation timed out.
    Timeout,
}

pub type Result<T> = core::result::Result<T, NetworkMboxError>;

/// Network Mailbox Hardware Interface Layer (HIL).
///
/// This trait abstracts the network mailbox hardware, supporting both sender
/// (requester) and receiver (target) flows. The network coprocessor typically
/// acts as the receiver/target when external agents send commands.
///
/// ## Receiver Flow (Network Coprocessor as Target)
///
/// 1. External agent acquires lock and writes command/data
/// 2. External agent sets execute
/// 3. Network coprocessor receives `request_received` callback
/// 4. Network coprocessor reads command and data
/// 5. Network coprocessor writes response data
/// 6. Network coprocessor sets target status with done=true
/// 7. External agent reads response and releases lock
///
/// ## Sender Flow (Network Coprocessor as Requester)
///
/// 1. Network coprocessor acquires lock
/// 2. Network coprocessor writes command, target user, and data
/// 3. Network coprocessor sets execute
/// 4. Target processes command and sets target status
/// 5. Network coprocessor receives `response_received` callback
/// 6. Network coprocessor reads response
/// 7. Network coprocessor releases lock
pub trait NetworkMailbox<'a> {
    /// Sends a command and associated data via the network mailbox (Sender/Requester mode).
    ///
    /// This acquires the lock, writes the command, target user, data, and
    /// sets execute. The caller will be notified via `response_received` when
    /// the target completes.
    ///
    /// # Arguments
    ///
    /// * `command` - The command identifier to send.
    /// * `target_user` - The target user ID for the command.
    /// * `request_data` - Iterator yielding the request payload dwords to transmit.
    /// * `dlen` - Number of bytes to send from `request_data`.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err(NetworkMboxError)` if the operation fails (e.g., mailbox locked).
    fn send_request(
        &self,
        command: u32,
        target_user: u32,
        request_data: impl Iterator<Item = u32>,
        dlen: usize,
    ) -> Result<()>;

    /// Writes a response to the network mailbox (Receiver/Target mode).
    ///
    /// This writes response data and updates DLEN. The caller should
    /// subsequently call `set_target_status` to signal completion.
    ///
    /// # Arguments
    ///
    /// * `response_data` - Iterator yielding the response payload dwords to write.
    /// * `dlen` - Number of bytes to write from `response_data`.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err(NetworkMboxError)` if the operation fails.
    fn send_response(&self, response_data: impl Iterator<Item = u32>, dlen: usize) -> Result<()>;

    /// Sets the target status of the network mailbox (Receiver/Target mode).
    ///
    /// This sets the target status register including the done bit to signal
    /// to the requester that processing is complete.
    ///
    /// # Arguments
    ///
    /// * `status` - The status to report to the requester.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err(NetworkMboxError)` if the operation fails.
    fn set_target_status(&self, status: NetworkMboxStatus) -> Result<()>;

    /// Sets the command status of the network mailbox.
    ///
    /// # Arguments
    ///
    /// * `status` - The command status to set.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err(NetworkMboxError)` if the operation fails.
    fn set_cmd_status(&self, status: NetworkMboxStatus) -> Result<()>;

    /// Returns the maximum size (in dwords) of the network mailbox SRAM.
    fn max_sram_dw_size(&self) -> usize;

    /// Restores the receive buffer for the mailbox.
    ///
    /// This method is intended to be called by the client after processing a
    /// received request to return the buffer for future use.
    ///
    /// # Arguments
    ///
    /// * `rx_buf` - The buffer to restore for receiving data.
    fn restore_rx_buffer(&self, rx_buf: &'static mut [u32]);

    /// Enables the network mailbox driver instance.
    fn enable(&self);

    /// Disables the network mailbox driver instance.
    fn disable(&self);

    /// Registers a client to receive network mailbox event callbacks.
    ///
    /// # Arguments
    ///
    /// * `client` - Reference to an object implementing `NetworkMailboxClient`.
    fn set_client(&self, client: &'a dyn NetworkMailboxClient);

    /// Poll for incoming requests or target done events.
    ///
    /// Must be called frequently from the main loop to process
    /// mailbox transactions.
    fn poll(&self);
}

/// Trait for clients that handle network mailbox events and callbacks.
///
/// Implement this trait to receive asynchronous notifications for network
/// mailbox operations.
pub trait NetworkMailboxClient {
    /// Called when a mailbox request is received (Receiver/Target mode).
    ///
    /// An external agent has sent a command via the network mailbox. The
    /// command and data are provided in the buffer. The client must call
    /// `restore_rx_buffer` on the driver after processing.
    ///
    /// # Arguments
    ///
    /// * `command` - The command identifier of the received request.
    /// * `user` - The AXI USER ID of the requester.
    /// * `rx_buf` - Buffer containing the received data (dwords).
    /// * `dlen` - Number of valid bytes in `rx_buf`.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the request was accepted for processing.
    /// * `Err(NetworkMboxError)` if the request could not be handled.
    fn request_received(
        &self,
        command: u32,
        user: u32,
        rx_buf: &'static mut [u32],
        dlen: usize,
    ) -> Result<()>;

    /// Called when a response is received from the target (Sender/Requester mode).
    ///
    /// The target has completed processing and set the target status. The
    /// response data and status are provided.
    ///
    /// # Arguments
    ///
    /// * `status` - The target status after processing.
    /// * `rx_buf` - Buffer containing the response data (dwords).
    /// * `dlen` - Number of valid bytes in `rx_buf`.
    fn response_received(
        &self,
        status: NetworkMboxTargetStatus,
        rx_buf: &'static mut [u32],
        dlen: usize,
    );

    /// Called when a send operation completes.
    ///
    /// # Arguments
    ///
    /// * `result` - Result of the send operation.
    fn send_done(&self, result: Result<()>);
}
