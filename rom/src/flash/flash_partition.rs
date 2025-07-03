// Licensed under the Apache-2.0 license

use crate::flash::hil::{FlashDrvError, FlashStorage};

/// Represents a partition within the flash memory.
///
/// A `FlashPartition` provides a view into a contiguous region of the underlying
/// flash, allowing for read, write, and erase operations within the
/// specified bounds. Each partition is associated with a name, a base offset,
/// and a length, and all operations are checked to ensure they do not exceed
/// the partition's boundaries.
///
/// # Fields
/// - `driver`: Reference to the flash storage controller driver.
/// - `name`: Name of the partition (for debugging or identification).
/// - `base_offset`: The starting offset of the partition within the flash.
/// - `length`: The size of the partition in bytes.
#[allow(dead_code)]
pub struct FlashPartition<'a> {
    driver: &'a dyn FlashStorage,
    name: &'static str,
    base_offset: usize,
    length: usize,
}

#[allow(dead_code)]
impl<'a> FlashPartition<'a> {
    /// Creates a new `FlashPartition` instance.
    ///
    /// # Arguments
    ///
    /// * `driver` - Reference to the flash storage controller.
    /// * `name` - Static string slice representing the partition name.
    /// * `base_offset` - The starting offset of the partition within the flash.
    /// * `length` - The length of the partition in bytes.
    ///
    /// # Returns
    ///
    /// Returns `Ok(FlashPartition)` if the partition fits within the flash capacity,
    /// otherwise returns `Err(FlashDrvError::SIZE)` if the partition exceeds the flash size.
    pub fn new(
        driver: &'a dyn FlashStorage,
        name: &'static str,
        base_offset: usize,
        length: usize,
    ) -> Result<Self, FlashDrvError> {
        let capacity = driver.capacity();
        if base_offset + length > capacity {
            return Err(FlashDrvError::SIZE);
        }
        Ok(FlashPartition {
            driver,
            name,
            base_offset,
            length,
        })
    }

    /// Reads data from the flash partition into the provided buffer, starting at the specified offset within the partition.
    ///
    /// # Arguments
    ///
    /// * `partition_offset` - The offset within the partition from which to start reading.
    /// * `buf` - The mutable buffer to fill with the read data.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the read operation is successful.
    /// Returns `Err(FlashDrvError::SIZE)` if the requested range exceeds the partition size, or propagates errors from the underlying flash controller.
    pub fn read(&self, partition_offset: usize, buf: &'a mut [u8]) -> Result<(), FlashDrvError> {
        if partition_offset + buf.len() > self.length {
            return Err(FlashDrvError::SIZE);
        }
        self.driver.read(buf, self.base_offset + partition_offset)
    }

    /// Writes data to the flash partition, starting at the specified offset within the partition.
    ///
    /// # Arguments
    ///
    /// * `partition_offset` - The offset within the partition at which to start writing.
    /// * `buf` - The buffer containing the data to write.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the write operation is successful.
    /// Returns `Err(FlashDrvError::SIZE)` if the write would exceed the partition size,
    /// or propagates errors from the underlying flash controller.
    pub fn write(&self, partition_offset: usize, buf: &[u8]) -> Result<(), FlashDrvError> {
        if partition_offset + buf.len() > self.length {
            return Err(FlashDrvError::SIZE);
        }
        self.driver.write(buf, self.base_offset + partition_offset)
    }

    /// Erases a region of the flash partition, starting at the specified offset within the partition.
    ///
    /// # Arguments
    ///
    /// * `partition_offset` - The offset within the partition at which to start erasing.
    /// * `len` - The number of bytes to erase.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the erase operation is successful.
    /// Returns `Err(FlashDrvError::SIZE)` if the erase range exceeds the partition size,
    /// or propagates errors from the underlying flash controller.
    pub fn erase(&self, partition_offset: usize, len: usize) -> Result<(), FlashDrvError> {
        if partition_offset + len > self.length {
            return Err(FlashDrvError::SIZE);
        }
        self.driver.erase(self.base_offset + partition_offset, len)
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
}
