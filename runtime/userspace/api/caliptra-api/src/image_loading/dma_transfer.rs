// Licensed under the Apache-2.0 license

extern crate alloc;
use alloc::boxed::Box;

use async_trait::async_trait;
use caliptra_mcu_libsyscall_caliptra::dma::{AXIAddr, DMAMapping};
use caliptra_mcu_libtock_platform::ErrorCode;

/// Generic trait for performing source-to-destination DMA transfers.
///
/// This trait abstracts the transfer of data from a source (identified
/// by offset) to an AXI destination address. Implementations can use
/// any transfer mechanism: direct DMA from a peripheral, buffered
/// copy through SRAM, memory-to-memory DMA, etc.
#[async_trait(?Send)]
pub trait DmaTransfer: DMAMapping {
    /// The maximum number of bytes that can be transferred in a single
    /// operation. The caller will chunk transfers to this size.
    fn max_transfer_size(&self) -> usize;

    /// Transfer `length` bytes starting at `src_offset` in the source
    /// directly to `dest_addr` on the AXI bus.
    async fn transfer(
        &self,
        src_offset: usize,
        dest_addr: AXIAddr,
        length: usize,
    ) -> Result<(), ErrorCode>;
}
