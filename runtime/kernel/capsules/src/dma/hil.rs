// Licensed under the Apache-2.0 license.

//! HIL Interface for Caliptra DMA Engine
use kernel::ErrorCode;

/// This trait provides the interfaces for managing DMA transfers.
pub trait Dma {
    /// Configure the DMA transfer with 64-bit source and destination addresses.
    ///
    /// # Arguments:
    /// - `byte_count`: Total bytes to transfer (must be aligned to AXI data width).
    /// - `block_size`: Size of individual blocks for transfer.
    /// - `src_addr`: Optional 64-bit source address for the transfer.
    /// - `dest_addr`: Optional 64-bit destination address for the transfer.
    ///
    /// Returns:
    /// - `Ok(())` if configuration is successful.
    /// - `Err(ErrorCode)` if parameters are invalid.
    fn configure_transfer(
        &self,
        byte_count: usize,
        block_size: usize,
        src_addr: Option<u64>,
        dest_addr: Option<u64>,
    ) -> Result<(), ErrorCode>;

    /// Start the configured DMA transfer.
    fn start_transfer(
        &self,
        read_route: DmaRoute,
        write_route: DmaRoute,
        fixed_addr: bool,
    ) -> Result<(), ErrorCode>;

    /// Poll the DMA status for transfer progress or completion.
    fn poll_status(&self) -> Result<DmaStatus, DmaError>;

    /// Push data into the WR FIFO for AHB -> AXI WR transfers.
    ///
    /// # Arguments:
    /// - `data`: Slice of data to be written (as bytes).
    fn write_fifo(&self, data: &[u8]) -> Result<(), DmaError>;

    /// Pop data from the RD FIFO for AXI RD -> AHB transfers.
    ///
    /// # Arguments:
    /// - `buffer`: Mutable slice to store the read data (as bytes).
    ///
    /// Returns:
    /// - `Ok(bytes_read)` indicating the number of bytes read.
    fn read_fifo(&self, buffer: &mut [u8]) -> Result<usize, DmaError>;

    /// Set a client for receiving DMA transfer events asynchronously.
    fn set_client(&self, client: &'static dyn DmaClient);
}

/// DMA Route configuration for Read/Write routes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DmaRoute {
    Disabled,
    AxiToAxi,
}

/// Represents the current status of the DMA transfer.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DmaStatus {
    TxnDone,        // Transaction complete
    RdFifoNotEmpty, // Read FIFO has data
    RdFifoFull,     // Read FIFO is full
    WrFifoNotFull,  // Write FIFO has room for more data
    WrFifoEmpty,    // Write FIFO is empty
}

/// Represents possible DMA errors.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DmaError {
    CommandError,     // General command error
    AxiReadError,     // AXI Read error
    AxiWriteError,    // AXI Write error
    MailboxNotLocked, // Mailbox lock not acquired
    RdFifoOverflow,   // Data overflow in Read FIFO
    RdFifoUnderflow,  // Data underflow in Read FIFO
    WrFifoOverflow,   // Data overflow in Write FIFO
    WrFifoUnderflow,  // Data underflow in Write FIFO
}

/// A client trait for handling asynchronous DMA transfer events.
pub trait DmaClient {
    /// Called when a DMA transfer completes successfully.
    fn transfer_complete(&self, status: DmaStatus);

    /// Called when a DMA transfer encounters an error.
    fn transfer_error(&self, error: DmaError);
}
