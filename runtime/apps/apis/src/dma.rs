// Licensed under the Apache-2.0 license

//! # DMA: A DMA Interface for AXI Source to AXI Destination Transfers
//!
//! This library provides an abstraction for performing asynchronous Direct Memory Access (DMA)
//! transfers between AXI source and AXI destination addresses.

use libtock_platform::allow_ro::AllowRo;
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;
/// DMA interface.
pub struct DMA<S: Syscalls>(S);

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
    pub async fn xfer<'a>(transaction: &DMATransaction<'a>) -> Result<(), ErrorCode> {
        Self::setup(transaction).await?;

        match transaction.source {
            DMASource::Buffer(buffer) => Self::xfer_src_buffer(buffer).await.map(|_| ()),
            DMASource::Address(_) => Self::xfer_src_address().await.map(|_| ()),
        }
    }

    async fn xfer_src_address() -> Result<(), ErrorCode> {
        let async_start = TockSubscribe::subscribe::<S>(DMA_DRIVER_NUM, dma_subscribe::XFER_DONE);
        S::command(DMA_DRIVER_NUM, dma_cmd::XFER_AXI_TO_AXI, 0, 0).to_result::<(), ErrorCode>()?;
        async_start.await.map(|_| ())
    }

    async fn xfer_src_buffer(buffer: &[u8]) -> Result<(), ErrorCode> {
        // Use `share::scope` to safely share the buffer with the kernel
        share::scope::<(AllowRo<_, DMA_DRIVER_NUM, { dma_buffer::LOCAL_SOURCE }>,), _, _>(
            |handle| {
                let allow_ro = handle.split().0;

                // Share the local buffer as the source
                S::allow_ro::<DefaultConfig, DMA_DRIVER_NUM, { dma_buffer::LOCAL_SOURCE }>(
                    allow_ro, buffer,
                )?;

                // Start the DMA transfer
                let async_start =
                    TockSubscribe::subscribe::<S>(DMA_DRIVER_NUM, dma_subscribe::XFER_DONE);
                S::command(DMA_DRIVER_NUM, dma_cmd::XFER_LOCAL_TO_AXI, 0, 0)
                    .to_result::<(), ErrorCode>()?;
                Ok(async_start)
            },
        )?
        .await
        .map(|_| ())
    }

    async fn setup<'a>(config: &DMATransaction<'a>) -> Result<(), ErrorCode> {
        let async_configure =
            TockSubscribe::subscribe::<S>(DMA_DRIVER_NUM, dma_subscribe::SET_BYTE_XFER_COUNT_DONE);
        S::command(
            DMA_DRIVER_NUM,
            dma_cmd::SET_BYTE_XFER_COUNT,
            config.byte_count as u32,
            0,
        )
        .to_result::<(), ErrorCode>()?;
        async_configure.await.map(|_| ())?;

        if let DMASource::Address(src_addr) = config.source {
            let async_src =
                TockSubscribe::subscribe::<S>(DMA_DRIVER_NUM, dma_subscribe::SET_SRC_DONE);
            S::command(
                DMA_DRIVER_NUM,
                dma_cmd::SET_SRC_ADDR,
                (src_addr & 0xFFFF_FFFF) as u32,
                (src_addr >> 32) as u32,
            )
            .to_result::<(), ErrorCode>()?;
            async_src.await.map(|_| ())?;
        }

        let async_dest =
            TockSubscribe::subscribe::<S>(DMA_DRIVER_NUM, dma_subscribe::SET_DEST_DONE);
        S::command(
            DMA_DRIVER_NUM,
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

const DMA_DRIVER_NUM: u32 = 0x8000_0008;

/// Command IDs used by the DMA interface.
mod dma_cmd {
    pub const SET_BYTE_XFER_COUNT: u32 = 0;
    pub const SET_SRC_ADDR: u32 = 1;
    pub const SET_DEST_ADDR: u32 = 2;
    pub const XFER_AXI_TO_AXI: u32 = 3;
    pub const XFER_LOCAL_TO_AXI: u32 = 4;
}

/// Buffer IDs for DMA
mod dma_buffer {
    /// Buffer ID for local buffers (read-only)
    pub const LOCAL_SOURCE: u32 = 0;
}

/// Subscription IDs for asynchronous notifications.
mod dma_subscribe {
    pub const SET_BYTE_XFER_COUNT_DONE: u32 = 0;
    pub const SET_SRC_DONE: u32 = 1;
    pub const SET_DEST_DONE: u32 = 2;
    pub const XFER_DONE: u32 = 3;
}
