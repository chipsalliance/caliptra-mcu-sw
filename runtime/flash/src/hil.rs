// Licensed under the Apache-2.0 license

//! Generic interface for flash storage access.

use core::result::Result;
use kernel::ErrorCode;

/// Simple interface for reading, writing and erasing the arbitrary length of data on flash storage. It is expected
/// that drivers for the flash storage access would implement this trait.
pub trait FlashStorage<'a> {
    fn set_client(&self, client: &'a dyn FlashStorageClient);

    /// Read `length` bytes starting at address `address` in to the provided
    /// buffer. The buffer must be at least `length` bytes long. The address
    /// must be in the address space of the physical storage.
    fn read(
        &self,
        buffer: &'static mut [u8],
        address: usize,
        length: usize,
    ) -> Result<(), ErrorCode>;

    /// Write `length` bytes starting at address `address` from the provided
    /// buffer. The buffer must be at least `length` bytes long. This address
    /// must be in the address space of the physical storage.
    fn write(
        &self,
        buffer: &'static mut [u8],
        address: usize,
        length: usize,
    ) -> Result<(), ErrorCode>;

    /// Erase `length` bytes starting at address `address`. The address must be
    /// in the address space of the physical storage.
    fn erase(&self, address: usize, length: usize) -> Result<(), ErrorCode>;
}

/// Client interface for flash storage.
pub trait FlashStorageClient {
    /// `read_done` is called when the implementor is finished reading in to the
    /// buffer. The callback returns the buffer and the number of bytes that
    /// were actually read.
    fn read_done(&self, buffer: &'static mut [u8], length: usize);

    /// `write_done` is called when the implementor is finished writing from the
    /// buffer. The callback returns the buffer and the number of bytes that
    /// were actually written.
    fn write_done(&self, buffer: &'static mut [u8], length: usize);

    /// `erase_done` is called when the implementor is finished erasing the
    /// storage. The callback returns the number of bytes that were actually
    /// erased.
    fn erase_done(&self, length: usize);
}
