// Licensed under the Apache-2.0 license

//! # DMA: A DMA Interface for AXI Source to AXI Destination Transfers
//!
//! This library provides an abstraction for performing asynchronous Direct Memory Access (DMA)
//! transfers between AXI source and AXI destination addresses.

use crate::DefaultSyscalls;
use core::marker::PhantomData;
use libtock_platform::{share, AllowRo, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;
/// DMA interface.
pub struct DMA<S: Syscalls = DefaultSyscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

/// Define type for AXI address (64-bit wide).
pub type AXIAddr = u64;

/// DMA address conversion utility.
pub trait DMAMapping: Send + Sync {
    /// Convert a local address in MCU SRAM to an AXI address addressable by the MCU DMA controller.
    fn mcu_sram_to_mcu_axi(&self, addr: u32) -> Result<AXIAddr, ErrorCode>;
    /// Convert a Caliptra AXI address to the MCU DMA accessible address.
    fn cptra_axi_to_mcu_axi(&self, addr: AXIAddr) -> Result<AXIAddr, ErrorCode>;
}

/// Configuration parameters for a DMA transfer.
#[derive(Debug, Clone)]
pub struct DMATransaction<'a> {
    /// Number of bytes to transfer.
    pub byte_count: usize,
    /// Source for the transfer.
    pub source: DMASource<'a>,
    /// Destination AXI address for the transfer.
    pub dest_addr: AXIAddr,
}

/// Represents the source of data for a DMA transfer.
#[derive(Debug, Clone)]
pub enum DMASource<'a> {
    /// AXI memory address as the source.
    Address(AXIAddr),
    /// A local buffer as the source.
    Buffer(&'a [u8]),
}

impl<S: Syscalls> Default for DMA<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> DMA<S> {
    pub fn new() -> Self {
        Self {
            syscall: PhantomData,
            driver_num: DMA_DRIVER_NUM,
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
    pub async fn xfer(&self, transaction: &DMATransaction<'_>) -> Result<(), ErrorCode> {
        self.setup(transaction)?;

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
        let async_start = TockSubscribe::subscribe::<S>(self.driver_num, dma_subscribe::XFER_DONE);

        share::scope::<AllowRo<_, DMA_DRIVER_NUM, { dma_ro_buffer::LOCAL_SOURCE }>, _, _>(
            |handle| {
                let allow_ro = handle;
                S::allow_ro::<DefaultConfig, DMA_DRIVER_NUM, { dma_ro_buffer::LOCAL_SOURCE }>(
                    allow_ro, buffer,
                )?;

                // Start the DMA transfer
                S::command(self.driver_num, dma_cmd::XFER_LOCAL_TO_AXI, 0, 0)
                    .to_result::<(), ErrorCode>()?;
                Ok(())
            },
        )?;

        async_start.await.map(|_| ())
    }

    fn setup(&self, config: &DMATransaction<'_>) -> Result<(), ErrorCode> {
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
pub const DMA_DRIVER_NUM: u32 = 0x9000_0000;

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
