// Licensed under the Apache-2.0 license

//! # DMA: A DMA Interface for AXI Source to AXI Destination Transfers
//!
//! This library provides an abstraction for performing asynchronous Direct Memory Access (DMA)
//! transfers between AXI source and AXI destination addresses.

use core::marker::PhantomData;
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;
/// DMA interface.
pub struct DMA<S: Syscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

/// Configuration parameters for a DMA transfer.
#[derive(Debug, Clone)]
pub struct DMATransaction<'a> {
    /// Number of bytes to transfer.
    pub byte_count: usize,
    /// Source for the transfer.
    pub source: DMASource<'a>,
    /// Destination address for the transfer.
    pub dest_addr: u64,
}

/// Represents the source of data for a DMA transfer.
#[derive(Debug, Clone)]
pub enum DMASource<'a> {
    /// A memory address as the source.
    Address(u64),
    /// A local buffer as the source.
    Buffer(&'a [u8]),
}

impl<S: Syscalls> DMA<S> {
    pub fn new(driver_num: u32) -> Self {
        Self {
            syscall: PhantomData,
            driver_num,
        }
    }

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
    pub async fn xfer<'a>(&self, transaction: &DMATransaction<'a>) -> Result<(), ErrorCode> {
        self.setup(transaction).await?;

        match transaction.source {
            DMASource::Buffer(buffer) => self.xfer_src_buffer(buffer).await.map(|_| ()),
            DMASource::Address(_) => self.xfer_src_address().await.map(|_| ()),
        }
    }

    async fn xfer_src_address(&self) -> Result<(), ErrorCode> {
        let async_start = TockSubscribe::subscribe::<S>(self.driver_num, dma_subscribe::XFER_DONE);
        S::command(self.driver_num, dma_cmd::XFER_AXI_TO_AXI, 0, 0).to_result::<(), ErrorCode>()?;
        async_start.await.map(|_| ())
    }

    async fn xfer_src_buffer(&self, buffer: &[u8]) -> Result<(), ErrorCode> {
        // Use `share::scope` to safely share the buffer with the kernel
        share::scope::<(), _, _>(|_| {
            let async_start = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                dma_subscribe::XFER_DONE,
                dma_ro_buffer::LOCAL_SOURCE,
                buffer,
            );

            // Start the DMA transfer
            S::command(self.driver_num, dma_cmd::XFER_LOCAL_TO_AXI, 0, 0)
                .to_result::<(), ErrorCode>()?;
            Ok(async_start)
        })?
        .await
        .map(|_| ())
    }

    async fn setup<'a>(&self, config: &DMATransaction<'a>) -> Result<(), ErrorCode> {
        S::command(
            self.driver_num,
            dma_cmd::SET_BYTE_XFER_COUNT,
            config.byte_count as u32,
            0,
        )
        .to_result::<(), ErrorCode>()?;

        if let DMASource::Address(src_addr) = config.source {
            S::command(
                self.driver_num,
                dma_cmd::SET_SRC_ADDR,
                (src_addr & 0xFFFF_FFFF) as u32,
                (src_addr >> 32) as u32,
            )
            .to_result::<(), ErrorCode>()?;
        }

        S::command(
            self.driver_num,
            dma_cmd::SET_DEST_ADDR,
            (config.dest_addr & 0xFFFF_FFFF) as u32,
            (config.dest_addr >> 32) as u32,
        )
        .to_result::<(), ErrorCode>()?;

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Command IDs and DMA-specific constants
// -----------------------------------------------------------------------------

// Driver number for the DMA interface
pub const DMA_DRIVER_NUM: u32 = 0x8000_0008;

/// Command IDs used by the DMA interface.
mod dma_cmd {
    pub const SET_BYTE_XFER_COUNT: u32 = 0;
    pub const SET_SRC_ADDR: u32 = 1;
    pub const SET_DEST_ADDR: u32 = 2;
    pub const XFER_AXI_TO_AXI: u32 = 3;
    pub const XFER_LOCAL_TO_AXI: u32 = 4;
}

/// Buffer IDs for DMA (read-only)
mod dma_ro_buffer {
    /// Buffer ID for local buffers (read-only)
    pub const LOCAL_SOURCE: u32 = 0;
}

/// Subscription IDs for asynchronous notifications.
mod dma_subscribe {
    pub const XFER_DONE: u32 = 0;
}
