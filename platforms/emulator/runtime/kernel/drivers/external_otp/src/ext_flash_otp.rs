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

    fn prepare_buffer(&self, value: [u8; 4]) -> Result<&'static mut [u8], ExternalOtpError> {
        let buffer = self.buffer.take().ok_or(ExternalOtpError::Busy)?;
        let Some(word) = buffer.first_chunk_mut::<4>() else {
            self.buffer.replace(buffer);
            return Err(ExternalOtpError::HardwareError);
        };
        *word = value;
        Ok(buffer)
    }

    fn read_word(buffer: &[u8]) -> Result<u32, ExternalOtpError> {
        buffer
            .first_chunk::<4>()
            .map(|bytes| u32::from_le_bytes(*bytes))
            .ok_or(ExternalOtpError::HardwareError)
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

        // Pre-fill with 0xFF for partial reads (< 4 bytes).
        let buffer = self.prepare_buffer([0xFF; 4])?;

        self.state.set(State::Reading);
        match self.flash.read(buffer, flash_addr, readable) {
            Ok(()) => Ok(()),
            Err((_, buffer)) => {
                self.buffer.replace(buffer);
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

        let buffer = self.prepare_buffer([0xFF; 4])?;

        self.state.set(State::WriteLockCheck {
            value,
            flash_offset,
            writable,
        });
        match self.flash.read(buffer, lock_addr, 4) {
            Ok(()) => Ok(()),
            Err((_, buffer)) => {
                self.buffer.replace(buffer);
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

        let buffer = self.prepare_buffer(LOCK_LOCKED.to_le_bytes())?;

        self.state.set(State::Locking);
        match self.flash.write(buffer, lock_addr, 4) {
            Ok(()) => Ok(()),
            Err((_, buffer)) => {
                self.buffer.replace(buffer);
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

        let buffer = self.prepare_buffer([0xFF; 4])?;

        self.state.set(State::LockChecking);
        match self.flash.read(buffer, lock_addr, 4) {
            Ok(()) => Ok(()),
            Err((_, buffer)) => {
                self.buffer.replace(buffer);
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
                let value = Self::read_word(buffer);
                self.buffer.replace(buffer);
                self.state.set(State::Idle);
                self.client.map(|c| c.read_done(value));
            }

            State::WriteLockCheck {
                value,
                flash_offset,
                writable,
            } => {
                // Check if the partition is locked.
                let error = match Self::read_word(buffer) {
                    Ok(LOCK_UNLOCKED) => None,
                    Ok(_) => Some(ExternalOtpError::PartitionLocked),
                    Err(error) => Some(error),
                };
                if let Some(error) = error {
                    self.buffer.replace(buffer);
                    self.state.set(State::Idle);
                    self.client.map(|c| c.write_done(Err(error)));
                    return;
                }

                // Partition is unlocked — proceed with the write.
                let val_bytes = value.to_le_bytes();
                let Some((destination, source)) =
                    buffer.get_mut(..writable).zip(val_bytes.get(..writable))
                else {
                    self.buffer.replace(buffer);
                    self.state.set(State::Idle);
                    self.client
                        .map(|c| c.write_done(Err(ExternalOtpError::HardwareError)));
                    return;
                };
                destination.copy_from_slice(source);

                self.state.set(State::Writing);
                match self.flash.write(buffer, flash_offset, writable) {
                    Ok(()) => {}
                    Err((_, buffer)) => {
                        self.buffer.replace(buffer);
                        self.state.set(State::Idle);
                        self.client
                            .map(|c| c.write_done(Err(ExternalOtpError::HardwareError)));
                    }
                }
            }

            State::LockChecking => {
                let locked = Self::read_word(buffer).map(|word| word != LOCK_UNLOCKED);
                self.buffer.replace(buffer);
                self.state.set(State::Idle);
                self.client.map(|c| c.lock_check_done(locked));
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

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::ErrorCode;

    struct TestFlash {
        write_buffer: TakeCell<'static, [u8]>,
        write_length: Cell<usize>,
    }

    impl<'a> FlashStorage<'a> for TestFlash {
        fn set_client(&self, _client: &'a dyn FlashStorageClient) {}

        fn read(
            &self,
            buffer: &'static mut [u8],
            _address: usize,
            _length: usize,
        ) -> Result<(), (ErrorCode, &'static mut [u8])> {
            Err((ErrorCode::NOSUPPORT, buffer))
        }

        fn write(
            &self,
            buffer: &'static mut [u8],
            _address: usize,
            length: usize,
        ) -> Result<(), (ErrorCode, &'static mut [u8])> {
            self.write_buffer.replace(buffer);
            self.write_length.set(length);
            Ok(())
        }

        fn erase(&self, _address: usize, _length: usize) -> Result<(), ErrorCode> {
            Err(ErrorCode::NOSUPPORT)
        }

        fn erase_size(&self) -> usize {
            1
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Completion {
        Read(Result<u32, ExternalOtpError>),
        Write(Result<(), ExternalOtpError>),
        Lock(Result<(), ExternalOtpError>),
        LockCheck(Result<bool, ExternalOtpError>),
    }

    struct TestClient(Cell<Option<Completion>>);

    impl ExternalOtpClient for TestClient {
        fn read_done(&self, result: Result<u32, ExternalOtpError>) {
            self.0.set(Some(Completion::Read(result)));
        }

        fn write_done(&self, result: Result<(), ExternalOtpError>) {
            self.0.set(Some(Completion::Write(result)));
        }

        fn lock_done(&self, result: Result<(), ExternalOtpError>) {
            self.0.set(Some(Completion::Lock(result)));
        }

        fn lock_check_done(&self, result: Result<bool, ExternalOtpError>) {
            self.0.set(Some(Completion::LockCheck(result)));
        }
    }

    #[test]
    fn operations_return_undersized_buffers_without_starting() {
        let partitions = [ExternalOtpPartitionInfo { id: 7, size: 8 }];
        for operation in 0..4 {
            let flash = TestFlash {
                write_buffer: TakeCell::empty(),
                write_length: Cell::new(0),
            };
            let client = TestClient(Cell::new(None));
            let buffer = Box::leak(Box::new([0xA5; 3]));
            let ptr = buffer.as_ptr();
            let driver = ExtFlashBackedExternalOtp::new(&partitions, &flash, 0, buffer);
            driver.set_client(&client);

            let result = match operation {
                0 => driver.read(7, 0),
                1 => driver.write(7, 0, 0x1234_5678),
                2 => driver.lock_partition(7),
                _ => driver.is_partition_locked(7),
            };

            assert_eq!(result, Err(ExternalOtpError::HardwareError));
            assert_eq!(driver.state.get(), State::Idle);
            let buffer = driver.buffer.take().unwrap();
            assert_eq!(buffer.as_ptr(), ptr);
            assert_eq!(buffer, &[0xA5; 3]);
            assert_eq!(client.0.get(), None);
            assert!(flash.write_buffer.is_none());
        }
    }

    #[test]
    fn read_callbacks_report_short_buffers_and_preserve_partial_read_fill() {
        let cases: &[(State, &[u8], usize, Completion)] = &[
            (
                State::Reading,
                &[0xff; 3],
                3,
                Completion::Read(Err(ExternalOtpError::HardwareError)),
            ),
            (
                State::WriteLockCheck {
                    value: 1,
                    flash_offset: 0,
                    writable: 4,
                },
                &[0xff; 3],
                3,
                Completion::Write(Err(ExternalOtpError::HardwareError)),
            ),
            (
                State::LockChecking,
                &[0xff; 3],
                3,
                Completion::LockCheck(Err(ExternalOtpError::HardwareError)),
            ),
            (
                State::Reading,
                &[0x78, 0xff, 0xff, 0xff],
                1,
                Completion::Read(Ok(0xffff_ff78)),
            ),
        ];
        for &(state, bytes, length, expected) in cases {
            let flash = TestFlash {
                write_buffer: TakeCell::empty(),
                write_length: Cell::new(0),
            };
            let client = TestClient(Cell::new(None));
            let buffer = Box::leak(bytes.to_vec().into_boxed_slice());
            let ptr = buffer.as_ptr();
            let driver = ExtFlashBackedExternalOtp::new(&[], &flash, 0, buffer);
            driver.set_client(&client);
            driver.state.set(state);

            driver.read_done(driver.buffer.take().unwrap(), length);

            assert_eq!(driver.state.get(), State::Idle);
            let buffer = driver.buffer.take().unwrap();
            assert_eq!(buffer.as_ptr(), ptr);
            assert_eq!(buffer, bytes);
            assert_eq!(client.0.get(), Some(expected));
            assert!(flash.write_buffer.is_none());
        }
    }

    #[test]
    fn lock_check_preserves_locking_and_rejects_invalid_write_ranges() {
        for (lock_word, writable, error) in [
            (LOCK_UNLOCKED, 0, None),
            (LOCK_UNLOCKED, 1, None),
            (LOCK_UNLOCKED, 4, None),
            (LOCK_UNLOCKED, 5, Some(ExternalOtpError::HardwareError)),
            (LOCK_LOCKED, 4, Some(ExternalOtpError::PartitionLocked)),
            (0xffff_fffe, 4, Some(ExternalOtpError::PartitionLocked)),
        ] {
            let flash = TestFlash {
                write_buffer: TakeCell::empty(),
                write_length: Cell::new(0),
            };
            let client = TestClient(Cell::new(None));
            let buffer = Box::leak(Box::new(lock_word.to_le_bytes()));
            let ptr = buffer.as_ptr();
            let driver = ExtFlashBackedExternalOtp::new(&[], &flash, 0, buffer);
            driver.set_client(&client);
            let value = 0x1234_5678u32;
            driver.state.set(State::WriteLockCheck {
                value,
                flash_offset: 0,
                writable,
            });

            driver.read_done(driver.buffer.take().unwrap(), 4);

            if let Some(error) = error {
                assert_eq!(driver.state.get(), State::Idle);
                assert_eq!(client.0.get(), Some(Completion::Write(Err(error))));
                assert!(flash.write_buffer.is_none());
                let buffer = driver.buffer.take().unwrap();
                assert_eq!(buffer.as_ptr(), ptr);
                assert_eq!(buffer, &lock_word.to_le_bytes());
            } else {
                assert_eq!(driver.state.get(), State::Writing);
                assert_eq!(client.0.get(), None);
                let buffer = flash.write_buffer.take().unwrap();
                assert_eq!(buffer.as_ptr(), ptr);
                assert_eq!(flash.write_length.get(), writable);
                assert_eq!(&buffer[..writable], &value.to_le_bytes()[..writable]);
                assert_eq!(&buffer[writable..], &[0xff; 4][writable..]);
                driver.write_done(buffer, writable);
                assert_eq!(driver.state.get(), State::Idle);
                assert_eq!(client.0.get(), Some(Completion::Write(Ok(()))));
            }
        }
    }
}
