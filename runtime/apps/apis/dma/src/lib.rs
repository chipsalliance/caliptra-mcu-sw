// Licensed under the Apache-2.0 license

//! # AsyncDMA: A DMA Interface for AXI Source to AXI Destination Transfers
//!
//! This library provides an abstraction for performing asynchronous Direct Memory Access (DMA)
//! transfers between AXI source and AXI destination addresses.

use libtock_platform::{ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

/// DMA interface.
pub struct AsyncDMA<const DRIVER_NUM: u32, S: Syscalls>(S);

/// Configuration parameters for a DMA transfer.
#[derive(Debug, Copy, Clone)]
pub struct DMATransaction {
    /// Number of bytes to transfer.
    pub byte_count: usize,
    /// Source address for the transfer.
    pub src_addr: u64,
    /// Destination address for the transfer.
    pub dest_addr: u64,
}

impl<const DRIVER_NUM: u32, S: Syscalls> AsyncDMA<DRIVER_NUM, S> {
    /// Do a DMA transfer.
    ///
    /// This method executes a DMA transfer based on the provided `DMATransaction` configuration.
    ///
    /// # Arguments
    /// * `transaction` - A `DMATransaction` struct containing the transfer details.
    ///
    /// # Returns
    /// * `Ok(())` if the transfer starts successfully.
    /// * `Err(ErrorCode)` if the transfer fails.
    pub async fn xfer(transaction: DMATransaction) -> Result<(), ErrorCode> {
        Self::setup(transaction).await?;

        let async_start = TockSubscribe::subscribe::<S>(DRIVER_NUM, dma_subscribe::XFER_DONE);
        S::command(DRIVER_NUM, dma_cmd::START, 0, 0).to_result::<(), ErrorCode>()?;
        async_start.await.map(|_| ())
    }

    async fn setup(config: DMATransaction) -> Result<(), ErrorCode> {
        let async_configure =
            TockSubscribe::subscribe::<S>(DRIVER_NUM, dma_subscribe::SET_BYTE_XFER_COUNT_DONE);
        S::command(
            DRIVER_NUM,
            dma_cmd::SET_BYTE_XFER_COUNT,
            config.byte_count as u32,
            0,
        )
        .to_result::<(), ErrorCode>()?;
        async_configure.await.map(|_| ())?;

        let async_src = TockSubscribe::subscribe::<S>(DRIVER_NUM, dma_subscribe::SET_SRC_DONE);
        S::command(
            DRIVER_NUM,
            dma_cmd::SET_SRC_ADDR,
            (config.src_addr & 0xFFFF_FFFF) as u32,
            (config.src_addr >> 32) as u32,
        )
        .to_result::<(), ErrorCode>()?;
        async_src.await.map(|_| ())?;

        let async_dest = TockSubscribe::subscribe::<S>(DRIVER_NUM, dma_subscribe::SET_DEST_DONE);
        S::command(
            DRIVER_NUM,
            dma_cmd::SET_DEST_ADDR,
            (config.dest_addr & 0xFFFF_FFFF) as u32,
            (config.dest_addr >> 32) as u32,
        )
        .to_result::<(), ErrorCode>()?;
        async_dest.await.map(|_| ())?;

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Command IDs and DMA-specific constants
// -----------------------------------------------------------------------------

/// Command IDs used by the DMA interface.
mod dma_cmd {
    pub const SET_BYTE_XFER_COUNT: u32 = 0;
    pub const SET_SRC_ADDR: u32 = 1;
    pub const SET_DEST_ADDR: u32 = 2;
    pub const START: u32 = 3;
}

/// Subscription IDs for asynchronous notifications.
mod dma_subscribe {
    pub const SET_BYTE_XFER_COUNT_DONE: u32 = 0;
    pub const SET_SRC_DONE: u32 = 1;
    pub const SET_DEST_DONE: u32 = 2;
    pub const XFER_DONE: u32 = 3;
}
