# Proposal: Full Flash Image Loading to SPI Flash via PLDM

## Problem

When the system boots via streaming boot (PLDM), images are downloaded
and loaded directly into memory at their target AXI addresses. However,
the SPI flash is not updated with the streamed content. This means:

1. If the system resets, it falls back to whatever was previously on
   flash, which may be stale or empty.
2. Flash and the running firmware are out of sync.

The customer requirement (from meeting notes) is: **when doing streaming
boot, the image should also be written back to SPI flash so flash stays
consistent with the streamed image.** Flash should act as a "follower"
copy of the booted image.

Importantly, the unit of transfer is the **full flash image** — the
complete binary blob containing the `FlashHeader`, all `ImageHeader`
entries (TOC), and every image payload (Caliptra FMC/RT, SoC manifest,
MCU RT, SoC images). This is the same layout that `FlashImageLoader`
expects when booting from flash. Writing individual images is not
sufficient; the entire flash image must be stored so that a subsequent
flash boot produces the same result as the streaming boot that preceded
it.

## Goals

1. Provide a mechanism to download the **complete flash image** (headers
   + TOC + all image payloads) via PLDM and write it to SPI flash as a
   single contiguous blob.
2. Reuse the existing image loader and PLDM infrastructure as much as
   possible.
3. The recommended flow is: perform streaming boot first (load
   individual images into memory for immediate execution), then
   re-download the full flash image and store it to SPI flash so flash
   is consistent for future flash-based boots.
4. The solution should work with the existing `FdOps` / PLDM firmware
   device model.

## Current Architecture

### Streaming Boot (`PldmImageLoader`)
- Downloads header, TOC, and individual images via PLDM.
- Each image is DMA'd directly to its target AXI load address.
- Flash is never written.
- Uses `StreamingFdOps` which implements `FdOps`.


## Proposed Design

### Approach: New `download_full_image` API on `PldmImageLoader` with a generic `ImageWriter` trait

Add a new method to `PldmImageLoader` that downloads the full flash
image (headers + TOC + all payloads) as a single contiguous blob via
PLDM and writes each received chunk to a caller-provided `ImageWriter`.
The `ImageWriter` trait is generic — it is not flash-specific — so
different backends can be plugged in (SPI flash, memory buffer, etc.).

### New method on `PldmImageLoader`: `download_full_image`

Add a `download_full_image` method that reuses the existing PLDM
infrastructure (`StreamingFdOps`, `pldm_client`) but instead of
loading individual images to AXI load addresses, downloads the
complete flash image blob and passes each chunk to the `ImageWriter`.

This method operates on the same PLDM session that `PldmImageLoader`
already manages. The UA sends the full flash image as a single PLDM
component, and the FD writes each received chunk via the writer.

```rust
impl<'a, D: DMAMapping + 'static> PldmImageLoader<'a, D> {
    /// Download the full flash image via PLDM and write it to the
    /// provided `ImageWriter`.
    ///
    /// This downloads the complete flash image blob (FlashHeader +
    /// all ImageHeaders + all image payloads) as a single contiguous
    /// transfer and writes each received chunk to `writer`.
    ///
    /// This is typically called after streaming boot completes, to
    /// persist the streamed image to SPI flash for future flash boots.
    pub async fn download_full_image(
        &self,
        writer: &dyn ImageWriter,
    ) -> Result<(), ErrorCode> {
        // Initialize a new PLDM session for the full image download
        pldm_client::initialize_pldm(
            self.spawner,
            self.params.descriptors,
            self.params.fw_params,
            self.dma_mapping,
        )
        .await?;

        // Get the total image size from the PLDM component info
        let total_size = pldm_client::pldm_get_total_component_size().await?;

        // Prepare the writer (e.g., erase flash)
        writer.prepare(total_size).await?;

        // Download the full image blob, writing each chunk via the writer
        let result = pldm_client::pldm_download_full_image(writer).await;

        if result.is_err() {
            self.finalize()?;
            return Err(ErrorCode::Fail);
        }

        // Finalize the writer
        writer.finalize().await?;

        Ok(())
    }
}
```

### New trait: `ImageWriter`

```rust
// runtime/userspace/api/caliptra-api/src/image_loading/image_writer.rs

use caliptra_mcu_libtock_platform::ErrorCode;

/// A generic writer for receiving a full flash image blob.
///
/// Each call to `write` delivers a chunk of the image at the given
/// offset. Implementations can write to flash, a memory buffer, or
/// any other storage backend.
#[async_trait(?Send)]
pub trait ImageWriter: Send + Sync {
    /// Prepare the writer for receiving an image of `total_size` bytes.
    /// Called once before any `write` calls. Implementations can use
    /// this to erase flash, allocate buffers, etc.
    async fn prepare(&self, total_size: usize) -> Result<(), ErrorCode>;

    /// Write `data` at `offset` within the image.
    /// Offsets are relative to the start of the full flash image blob.
    async fn write(&self, offset: usize, data: &[u8]) -> Result<(), ErrorCode>;

    /// Called once after all data has been written. Implementations
    /// can use this to finalize (e.g., verify checksums, write a
    /// validity marker).
    async fn finalize(&self) -> Result<(), ErrorCode>;
}
```

### SPI flash implementation: `FlashImageWriter`

### Recommended Flow: Streaming Boot, Then Full Flash Image Download

The recommended combined flow is:

```
1. Streaming boot (PldmImageLoader::load_and_authorize)
   ├── Download header + TOC via PLDM
   ├── For each image: download via PLDM → DMA to AXI load address
   ├── Authorize each image via Caliptra mailbox
   └── System is now running from memory

2. Full flash image download (PldmImageLoader::download_full_image)
   ├── Initiate a new PLDM session
   ├── Writer::prepare() — e.g., erase SPI flash target region
   ├── Download the complete flash image (headers + TOC + all images)
   │   as a single contiguous blob → Writer::write() for each chunk
   ├── Writer::finalize()
   └── SPI flash now contains the full image for future flash boots
```

Usage example:

```rust
// Phase 1: Streaming boot (existing flow, unchanged)
let pldm_loader = PldmImageLoader::new(&pldm_params, spawner, &dma_mapping);
for image_id in image_ids {
    pldm_loader.load_and_authorize(image_id).await?;
}
pldm_loader.finalize()?;
// System is now booted from streamed images

// Phase 2: Persist the full flash image to SPI flash
let flash = SpiFlash::new(FLASH_DRIVER_NUM);
let writer = FlashImageWriter::new(flash, 0);
pldm_loader.download_full_image(&writer).await?;
// SPI flash now has the complete image for future flash boots
```
