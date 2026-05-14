// Licensed under the Apache-2.0 license

//! External SRAM-backed ExternalOTP.
//!
//! OTP partition data is stored in External SRAM at a configurable base address.
//! Reads and writes transfer a single u32 (4 bytes) at a time via DMA between
//! MCU SRAM and External SRAM.
//!
//! ## SRAM layout
//!
//! ```text
//! external_sram_base
//!   ├── partition 0 data  (partitions[0].size bytes)
//!   ├── partition 1 data  (partitions[1].size bytes)
//!   ├── ...
//!   └── lock region       (4 bytes per partition)
//!         ├── lock word 0   (0 = unlocked, non-zero = locked)
//!         ├── lock word 1
//!         └── ...
//! ```

use caliptra_mcu_dma_driver::hil::{DMAStatus, DmaRoute, DMA};
use caliptra_mcu_external_otp_driver::hil::{
    ExternalOtp, ExternalOtpError, ExternalOtpPartitionInfo,
};

/// DMA-backed ExternalOTP driver.
///
/// OTP partition data lives in External SRAM. DMA transfers move individual
/// u32 values between a local buffer (in MCU SRAM) and External SRAM.
pub struct ExtSramBackedExternalOtp<'a> {
    /// Partition table describing available partitions.
    partitions: &'a [ExternalOtpPartitionInfo],
    /// DMA controller for External SRAM access.
    dma: &'a dyn DMA,
    /// Base address of OTP data in External SRAM (AXI address space).
    external_sram_base: u64,
}

impl<'a> ExtSramBackedExternalOtp<'a> {
    /// Create a new DMA-backed ExternalOTP.
    ///
    /// # Arguments
    /// - `partitions`: Partition table. Partitions are laid out sequentially in
    ///   External SRAM starting at `external_sram_base`.
    /// - `dma`: Reference to the DMA controller.
    /// - `external_sram_base`: AXI base address in External SRAM for OTP data.
    pub fn new(
        partitions: &'a [ExternalOtpPartitionInfo],
        dma: &'a dyn DMA,
        external_sram_base: u64,
    ) -> Self {
        Self {
            partitions,
            dma,
            external_sram_base,
        }
    }

    /// Compute the byte offset within storage for a given partition.
    fn partition_storage_offset(&self, partition_id: u32) -> Option<(u32, u32)> {
        let mut offset = 0u32;
        for p in self.partitions {
            if p.id == partition_id {
                return Some((offset, p.size));
            }
            offset += p.size;
        }
        None
    }

    /// Byte offset of the lock region (immediately after all partition data).
    fn lock_region_offset(&self) -> u32 {
        self.partitions.iter().map(|p| p.size).sum()
    }

    /// Index of a partition in the partition table (for lock word addressing).
    fn partition_index(&self, partition_id: u32) -> Option<usize> {
        self.partitions.iter().position(|p| p.id == partition_id)
    }

    /// Read or write a lock word for a partition via DMA.
    fn lock_word_addr(&self, partition_idx: usize) -> u64 {
        let lock_offset = self.lock_region_offset() + (partition_idx as u32) * 4;
        self.external_sram_base + lock_offset as u64
    }

    /// Perform a DMA transfer and poll for completion.
    fn dma_transfer(
        &self,
        src_addr: u64,
        dst_addr: u64,
        len: usize,
    ) -> Result<(), ExternalOtpError> {
        self.dma
            .configure_transfer(len, 1, Some(src_addr), Some(dst_addr))
            .map_err(|_| ExternalOtpError::HardwareError)?;

        self.dma
            .start_transfer(DmaRoute::AxiToAxi, DmaRoute::AxiToAxi, false)
            .map_err(|_| ExternalOtpError::HardwareError)?;

        // Poll for completion
        loop {
            match self.dma.poll_status() {
                Ok(DMAStatus::TxnDone) => return Ok(()),
                Ok(_) => continue,
                Err(_) => return Err(ExternalOtpError::HardwareError),
            }
        }
    }
}

impl ExternalOtp for ExtSramBackedExternalOtp<'_> {
    fn read(&self, partition: u32, offset: u32) -> Result<u32, ExternalOtpError> {
        let (base, size) = self
            .partition_storage_offset(partition)
            .ok_or(ExternalOtpError::InvalidPartition)?;

        if offset + 4 > size {
            return Err(ExternalOtpError::OutOfBounds);
        }

        let mut buf = [0u8; 4];
        let sram_offset = base + offset;
        let ext_addr = self.external_sram_base + sram_offset as u64;
        let buf_addr = buf.as_mut_ptr() as u64;

        self.dma_transfer(ext_addr, buf_addr, 4)?;

        Ok(u32::from_le_bytes(buf))
    }

    fn write(&self, partition: u32, offset: u32, value: u32) -> Result<(), ExternalOtpError> {
        // Check lock before writing.
        if self.is_partition_locked(partition)? {
            return Err(ExternalOtpError::PartitionLocked);
        }

        let (base, size) = self
            .partition_storage_offset(partition)
            .ok_or(ExternalOtpError::InvalidPartition)?;

        if offset + 4 > size {
            return Err(ExternalOtpError::OutOfBounds);
        }

        let buf = value.to_le_bytes();
        let sram_offset = base + offset;
        let ext_addr = self.external_sram_base + sram_offset as u64;
        let buf_addr = buf.as_ptr() as u64;

        self.dma_transfer(buf_addr, ext_addr, 4)
    }

    fn lock_partition(&self, partition: u32) -> Result<(), ExternalOtpError> {
        let idx = self
            .partition_index(partition)
            .ok_or(ExternalOtpError::InvalidPartition)?;

        let lock_addr = self.lock_word_addr(idx);
        let buf = 1u32.to_le_bytes();
        let buf_addr = buf.as_ptr() as u64;

        self.dma_transfer(buf_addr, lock_addr, 4)
    }

    fn is_partition_locked(&self, partition: u32) -> Result<bool, ExternalOtpError> {
        let idx = self
            .partition_index(partition)
            .ok_or(ExternalOtpError::InvalidPartition)?;

        let lock_addr = self.lock_word_addr(idx);
        let mut buf = [0u8; 4];
        let buf_addr = buf.as_mut_ptr() as u64;

        self.dma_transfer(lock_addr, buf_addr, 4)?;

        Ok(u32::from_le_bytes(buf) != 0)
    }

    fn partition_info(&self, partition: u32) -> Option<&ExternalOtpPartitionInfo> {
        self.partitions.iter().find(|p| p.id == partition)
    }

    fn partition_count(&self) -> usize {
        self.partitions.len()
    }
}
