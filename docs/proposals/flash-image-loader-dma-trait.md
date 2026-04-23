# Proposal: Generic DMA Transfer Trait for FlashImageLoader

## Problem

The current `FlashImageLoader` implementation in
`runtime/userspace/api/caliptra-api/src/image_loading/flash_client.rs`
performs image loading in a two-step copy per chunk:

```
Flash Storage → stack buffer [0u8; 128] → DMA → target AXI address
```

The `flash_load_image` function allocates a 128-byte stack buffer, reads
from flash into it via `SpiFlash::read`, converts the buffer pointer to an
AXI address, and then issues a DMA transfer from the buffer to the
destination. This means every chunk is touched twice, and the transfer
size is capped at 128 bytes, resulting in many small syscall round-trips
for large images.

```rust
// Current implementation (simplified)
while remaining_size > 0 {
    let transfer_size = remaining_size.min(128);
    let mut buffer = [0u8; 128];                       // temp buffer on stack
    flash.read(current_offset, transfer_size, &mut buffer).await?;  // flash → buffer
    let src = dma_mapping.mcu_sram_to_mcu_axi(buffer.as_ptr() as u32)?;
    dma_syscall.xfer(&DMATransaction {
        byte_count: transfer_size,
        source: DMASource::Address(src),
        dest_addr: current_address,
    }).await?;                                          // buffer → destination
    // advance offsets...
}
```

On platforms with a DMA engine that can drive transfers directly from the
flash controller's AXI interface to the target address, this intermediate
copy is unnecessary and a performance bottleneck.

## Goals

1. Introduce a generic `DMATransfer` trait that abstracts a
   source-to-destination DMA operation, allowing platforms to provide
   optimized transfer implementations (e.g., direct flash-to-AXI DMA)
   without the temporary buffer.
2. Keep the existing buffered path as a fallback for platforms without
   direct DMA capability.
3. Minimize API surface change — the `ImageLoader` trait and its callers
   should not need modification.
4. Support larger transfer sizes when the hardware allows it.
5. Keep the trait generic so it can be reused for other source-to-
   destination transfer scenarios beyond flash (e.g., memory-to-memory,
   peripheral-to-memory).

## Proposed Design

### New trait: `DMATransfer`

Introduce a generic trait that abstracts a source-to-destination DMA
transfer. The trait is not flash-specific — it describes any transfer
from a source (identified by offset) to an AXI destination. Platforms
implement this trait to provide optimized transfer paths.

```rust
// runtime/userspace/api/caliptra-api/src/image_loading/dma_transfer.rs

use caliptra_mcu_libsyscall_caliptra::dma::AXIAddr;
use caliptra_mcu_libtock_platform::ErrorCode;

/// Generic trait for performing source-to-destination DMA transfers.
///
/// This trait abstracts the transfer of data from a source (identified
/// by offset) to an AXI destination address. Implementations can use
/// any transfer mechanism: direct DMA from a peripheral, buffered
/// copy through SRAM, memory-to-memory DMA, etc.
///
/// For flash image loading, the source offset corresponds to a flash
/// address, but the trait itself is not flash-specific.
#[async_trait(?Send)]
pub trait DMATransfer: Send + Sync {
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
```

### Fallback implementation: `BufferedFlashDMA`

For platforms that do not have direct flash-to-AXI DMA, provide a
flash-backed implementation that preserves the current behavior (read
flash into buffer, then DMA from buffer to destination):

```rust
/// Flash-backed DMATransfer that buffers through SRAM, matching the
/// current behavior. Reads from SPI flash into a stack buffer, then
/// DMAs from the buffer to the destination.
pub struct BufferedFlashDMA<'a, D: DMAMapping> {
    flash: &'a FlashSyscall,
    dma_mapping: &'a D,
}

impl<'a, D: DMAMapping> BufferedFlashDMA<'a, D> {
    pub fn new(flash: &'a FlashSyscall, dma_mapping: &'a D) -> Self {
        Self { flash, dma_mapping }
    }
}

#[async_trait(?Send)]
impl<D: DMAMapping> DMATransfer for BufferedFlashDMA<'_, D> {
    fn max_transfer_size(&self) -> usize {
        128 // matches current MAX_DMA_TRANSFER_SIZE
    }

    async fn transfer(
        &self,
        src_offset: usize,
        dest_addr: AXIAddr,
        length: usize,
    ) -> Result<(), ErrorCode> {
        let dma_syscall = DMASyscall::new();
        let mut buffer = [0u8; 128];
        self.flash
            .read(src_offset, length, &mut buffer[..length])
            .await?;
        let source_address = self.dma_mapping
            .mcu_sram_to_mcu_axi(buffer.as_ptr() as u32)?;
        dma_syscall.xfer(&DMATransaction {
            byte_count: length,
            source: DMASource::Address(source_address),
            dest_addr,
        }).await
    }
}
```

### Updated `FlashImageLoader`

`FlashImageLoader` becomes generic over the `DMATransfer` trait
instead of only over `DMAMapping`:

```rust
pub struct FlashImageLoader<T: DMATransfer + 'static> {
    mailbox: Mailbox,
    flash: FlashSyscall,
    dma_transfer: &'static T,
}

impl<T: DMATransfer + 'static> FlashImageLoader<T> {
    pub fn new(flash_syscall: FlashSyscall, dma_transfer: &'static T) -> Self {
        Self {
            mailbox: Mailbox::new(),
            flash: flash_syscall,
            dma_transfer,
        }
    }
}
```

### Updated `flash_load_image`

The function is simplified to delegate to the trait:

```rust
pub async fn flash_load_image(
    dma_transfer: &impl DMATransfer,
    load_address: AXIAddr,
    offset: usize,
    img_size: usize,
) -> Result<(), ErrorCode> {
    let max_xfer = dma_transfer.max_transfer_size();
    let mut remaining = img_size;
    let mut current_offset = offset;
    let mut current_addr = load_address;

    while remaining > 0 {
        let xfer_size = remaining.min(max_xfer);
        dma_transfer.transfer(current_offset, current_addr, xfer_size).await?;
        remaining -= xfer_size;
        current_offset += xfer_size;
        current_addr += xfer_size as u64;
    }

    Ok(())
}
```

### Platform-specific direct DMA example

A platform with a flash controller that supports DMA read to an AXI
destination would implement the trait like this:

```rust
pub struct DirectFlashDMA {
    // Platform-specific handles to flash controller + DMA engine
}

#[async_trait(?Send)]
impl DMATransfer for DirectFlashDMA {
    fn max_transfer_size(&self) -> usize {
        4096 // platform can do larger transfers
    }

    async fn transfer(
        &self,
        src_offset: usize,
        dest_addr: AXIAddr,
        length: usize,
    ) -> Result<(), ErrorCode> {
        // Program flash controller to read from src_offset
        // Program DMA engine destination to dest_addr
        // Start transfer and wait for completion
        // ... platform-specific implementation ...
        Ok(())
    }
}
```