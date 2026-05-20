// Licensed under the Apache-2.0 license

//! Async flash-backed ExternalOTP driver.
//!
//! OTP partition data is stored in flash via the kernel's async
//! [`FlashStorage`](caliptra_mcu_flash_driver::hil::FlashStorage) trait. All
//! byte-level reads and writes go through the flash mux, avoiding the
//! dual-driver conflict that occurred with the synchronous `SyncFlashCtrl`.
//!
//! ## Flash partition layout
//!
//! ```text
//! base_offset + 0
//!   ├── OTP partition 0 data  (partitions[0].size bytes)
//!   ├── OTP partition 1 data  (partitions[1].size bytes)
//!   ├── ...
//!   └── lock region           (4 bytes per OTP partition)
//!         ├── lock word 0   (0xFFFFFFFF = unlocked, any other = locked)
//!         ├── lock word 1
//!         └── ...
//! ```

use caliptra_mcu_external_otp_driver::hil::{
    ExternalOtp, ExternalOtpClient, ExternalOtpError, ExternalOtpPartitionInfo,
};
use caliptra_mcu_flash_driver::hil::{FlashStorage, FlashStorageClient};
use core::cell::Cell;
use kernel::utilities::cells::{OptionalCell, TakeCell};

/// Lock word value indicating an unlocked partition (erased flash state).
const LOCK_UNLOCKED: u32 = 0xFFFF_FFFF;
/// Lock word value indicating a locked partition.
const LOCK_LOCKED: u32 = 0x0000_0000;

/// Internal state machine states.
#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    /// No operation in progress.
    Idle,
    /// Reading OTP data; callback delivers the value.
    Reading,
    /// Checking lock word before a write; on completion we proceed to write data.
    WriteLockCheck {
        /// The value to write once the lock check passes.
        value: u32,
        /// Absolute flash address for the OTP data.
        flash_offset: usize,
        /// Number of bytes to write (≤ 4).
        writable: usize,
    },
    /// Writing OTP data.
    Writing,
    /// Writing a lock word.
    Locking,
    /// Reading a lock word for `is_partition_locked`.
    LockChecking,
}

/// Async flash-backed ExternalOTP driver.
pub struct ExtFlashBackedExternalOtp<'a> {
    /// OTP partition table.
    partitions: &'a [ExternalOtpPartitionInfo],
    /// Underlying async flash storage.
    flash: &'a dyn FlashStorage<'a>,
    /// Base offset in flash where OTP region starts.
    base_offset: usize,
    /// Client to notify on completion.
    client: OptionalCell<&'a dyn ExternalOtpClient>,
    /// Buffer for 4-byte flash reads/writes.
    buffer: TakeCell<'static, [u8]>,
    /// Current operation state.
    state: Cell<State>,
}

impl<'a> ExtFlashBackedExternalOtp<'a> {
    /// Create a new async flash-backed ExternalOTP.
    ///
    /// # Arguments
    /// - `partitions`: OTP partition table.
    /// - `flash`: Async flash storage driver (e.g. `FlashStorageToPages`).
    /// - `base_offset`: Byte offset in flash where the OTP region starts.
    /// - `buffer`: A 4-byte `&'static mut` buffer for flash I/O.
    pub fn new(
        partitions: &'a [ExternalOtpPartitionInfo],
        flash: &'a dyn FlashStorage<'a>,
        base_offset: usize,
        buffer: &'static mut [u8],
    ) -> Self {
        Self {
            partitions,
            flash,
            base_offset,
            client: OptionalCell::empty(),
            buffer: TakeCell::new(buffer),
            state: Cell::new(State::Idle),
        }
    }

    /// Compute the byte offset within the OTP region for a given partition.
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

    /// Index of a partition in the table.
    fn partition_index(&self, partition_id: u32) -> Option<usize> {
        self.partitions.iter().position(|p| p.id == partition_id)
    }

    /// Absolute flash address of the lock word for a partition.
    fn lock_word_flash_addr(&self, partition_idx: usize) -> usize {
        self.base_offset + (self.lock_region_offset() + (partition_idx as u32) * 4) as usize
    }
}

impl<'a> ExternalOtp<'a> for ExtFlashBackedExternalOtp<'a> {
    fn set_client(&self, client: &'a dyn ExternalOtpClient) {
        self.client.set(client);
    }

    fn read(&self, partition: u32, offset: u32) -> Result<(), ExternalOtpError> {
        if self.state.get() != State::Idle {
            return Err(ExternalOtpError::Busy);
        }

        let (base, size) = self
            .partition_storage_offset(partition)
            .ok_or(ExternalOtpError::InvalidPartition)?;

        if offset >= size {
            return Err(ExternalOtpError::OutOfBounds);
        }

        let readable = (size - offset).min(4) as usize;
        let flash_addr = self.base_offset + (base + offset) as usize;

        let buffer = self.buffer.take().ok_or(ExternalOtpError::Busy)?;
        // Pre-fill with 0xFF for partial reads (< 4 bytes).
        buffer[..4].copy_from_slice(&[0xFF; 4]);

        self.state.set(State::Reading);
        match self.flash.read(buffer, flash_addr, readable) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.state.set(State::Idle);
                Err(ExternalOtpError::HardwareError)
            }
        }
    }

    fn write(&self, partition: u32, offset: u32, value: u32) -> Result<(), ExternalOtpError> {
        if self.state.get() != State::Idle {
            return Err(ExternalOtpError::Busy);
        }

        let (base, size) = self
            .partition_storage_offset(partition)
            .ok_or(ExternalOtpError::InvalidPartition)?;

        if offset >= size {
            return Err(ExternalOtpError::OutOfBounds);
        }

        let writable = (size - offset).min(4) as usize;
        let flash_offset = self.base_offset + (base + offset) as usize;

        // First, check if partition is locked by reading the lock word.
        let idx = self
            .partition_index(partition)
            .ok_or(ExternalOtpError::InvalidPartition)?;
        let lock_addr = self.lock_word_flash_addr(idx);

        let buffer = self.buffer.take().ok_or(ExternalOtpError::Busy)?;
        buffer[..4].copy_from_slice(&[0xFF; 4]);

        self.state.set(State::WriteLockCheck {
            value,
            flash_offset,
            writable,
        });
        match self.flash.read(buffer, lock_addr, 4) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.state.set(State::Idle);
                Err(ExternalOtpError::HardwareError)
            }
        }
    }

    fn lock_partition(&self, partition: u32) -> Result<(), ExternalOtpError> {
        if self.state.get() != State::Idle {
            return Err(ExternalOtpError::Busy);
        }

        let idx = self
            .partition_index(partition)
            .ok_or(ExternalOtpError::InvalidPartition)?;
        let lock_addr = self.lock_word_flash_addr(idx);

        let buffer = self.buffer.take().ok_or(ExternalOtpError::Busy)?;
        buffer[..4].copy_from_slice(&LOCK_LOCKED.to_le_bytes());

        self.state.set(State::Locking);
        match self.flash.write(buffer, lock_addr, 4) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.state.set(State::Idle);
                Err(ExternalOtpError::HardwareError)
            }
        }
    }

    fn is_partition_locked(&self, partition: u32) -> Result<(), ExternalOtpError> {
        if self.state.get() != State::Idle {
            return Err(ExternalOtpError::Busy);
        }

        let idx = self
            .partition_index(partition)
            .ok_or(ExternalOtpError::InvalidPartition)?;
        let lock_addr = self.lock_word_flash_addr(idx);

        let buffer = self.buffer.take().ok_or(ExternalOtpError::Busy)?;
        buffer[..4].copy_from_slice(&[0xFF; 4]);

        self.state.set(State::LockChecking);
        match self.flash.read(buffer, lock_addr, 4) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.state.set(State::Idle);
                Err(ExternalOtpError::HardwareError)
            }
        }
    }

    fn partition_info(&self, partition: u32) -> Option<&ExternalOtpPartitionInfo> {
        self.partitions.iter().find(|p| p.id == partition)
    }

    fn partition_count(&self) -> usize {
        self.partitions.len()
    }
}

impl FlashStorageClient for ExtFlashBackedExternalOtp<'_> {
    fn read_done(&self, buffer: &'static mut [u8], _length: usize) {
        let state = self.state.get();
        match state {
            State::Reading => {
                let mut word_buf = [0xFFu8; 4];
                word_buf.copy_from_slice(&buffer[..4]);
                let value = u32::from_le_bytes(word_buf);
                self.buffer.replace(buffer);
                self.state.set(State::Idle);
                self.client.map(|c| c.read_done(Ok(value)));
            }

            State::WriteLockCheck {
                value,
                flash_offset,
                writable,
            } => {
                // Check if the partition is locked.
                let mut lock_buf = [0u8; 4];
                lock_buf.copy_from_slice(&buffer[..4]);
                let lock_word = u32::from_le_bytes(lock_buf);

                if lock_word != LOCK_UNLOCKED {
                    // Partition is locked — return error.
                    self.buffer.replace(buffer);
                    self.state.set(State::Idle);
                    self.client
                        .map(|c| c.write_done(Err(ExternalOtpError::PartitionLocked)));
                    return;
                }

                // Partition is unlocked — proceed with the write.
                let val_bytes = value.to_le_bytes();
                buffer[..writable].copy_from_slice(&val_bytes[..writable]);

                self.state.set(State::Writing);
                match self.flash.write(buffer, flash_offset, writable) {
                    Ok(()) => {}
                    Err(_) => {
                        self.state.set(State::Idle);
                        self.client
                            .map(|c| c.write_done(Err(ExternalOtpError::HardwareError)));
                    }
                }
            }

            State::LockChecking => {
                let mut lock_buf = [0u8; 4];
                lock_buf.copy_from_slice(&buffer[..4]);
                let lock_word = u32::from_le_bytes(lock_buf);
                let locked = lock_word != LOCK_UNLOCKED;
                self.buffer.replace(buffer);
                self.state.set(State::Idle);
                self.client.map(|c| c.lock_check_done(Ok(locked)));
            }

            _ => {
                // Unexpected state — return buffer and reset.
                self.buffer.replace(buffer);
                self.state.set(State::Idle);
            }
        }
    }

    fn write_done(&self, buffer: &'static mut [u8], _length: usize) {
        let state = self.state.get();
        self.buffer.replace(buffer);
        self.state.set(State::Idle);

        match state {
            State::Writing => {
                self.client.map(|c| c.write_done(Ok(())));
            }
            State::Locking => {
                self.client.map(|c| c.lock_done(Ok(())));
            }
            _ => {
                // Unexpected state — ignore.
            }
        }
    }

    fn erase_done(&self, _length: usize) {
        // OTP never erases — ignore.
    }
}
