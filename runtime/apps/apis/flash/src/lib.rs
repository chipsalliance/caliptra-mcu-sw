// Licensed under the Apache-2.0 license

// Flash userspace library

#![no_std]

use core::marker::PhantomData;
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

pub struct SpiFlash<S: Syscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlashCapacity(pub u32);

/// Represents an asynchronous SPI flash memory interface.
///
/// This struct provides methods to interact with SPI flash memory in an asynchronous manner,
/// allowing for non-blocking read, write and erase operations.
impl<S: Syscalls> SpiFlash<S> {
    /// Creates a new instance of `SpiFlash`.
    ///
    /// # Arguments
    ///
    /// * `driver_num` - The driver number associated with the SPI flash.
    ///
    /// # Returns
    /// A new instance of `SpiFlash`.
    pub fn new(driver_num: u32) -> Self {
        Self {
            syscall: PhantomData,
            driver_num,
        }
    }

    /// Checks if the SPI flash exists.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the SPI flash exists.
    /// * `Err(ErrorCode)` if there is an error.
    pub fn exists(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, flash_storage_cmd::EXISTS, 0, 0).to_result()
    }

    /// Gets the capacity of the SPI flash memory that is available to userspace.
    ///
    /// # Returns
    ///
    /// * `Ok(FlashCapacity)` with the capacity of the SPI flash memory.
    /// * `Err(ErrorCode)` if there is an error.
    pub fn get_capacity(&self) -> Result<FlashCapacity, ErrorCode> {
        S::command(self.driver_num, flash_storage_cmd::CAPACITY, 0, 0)
            .to_result()
            .map(FlashCapacity)
    }

    /// Reads data from the SPI flash memory in an asynchronous manner.
    ///
    /// # Arguments
    /// * `address` - The address in the SPI flash memory to read from.
    /// * `len` - The number of bytes to read.
    /// * `buf` - The buffer to read the data into. The buffer must be at least `len` bytes long.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the read operation is successful.
    /// * `Err(ErrorCode)` if there is an error.
    pub async fn read(&self, address: usize, len: usize, buf: &mut [u8]) -> Result<(), ErrorCode> {
        if buf.len() < len {
            return Err(ErrorCode::NoMem);
        }

        share::scope::<(), _, _>(|_handle| {
            let sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                subscribe::READ_DONE,
                rw_allow::READ,
                buf,
            );

            S::command(
                self.driver_num,
                flash_storage_cmd::READ,
                address as u32,
                len as u32,
            )
            .to_result::<(), ErrorCode>()?;

            Ok(sub)
        })?
        .await?;

        Ok(())
    }

    pub async fn write(&self, address: usize, len: usize, buf: &[u8]) -> Result<(), ErrorCode> {
        if buf.len() < len {
            return Err(ErrorCode::NoMem);
        }

        share::scope::<(), _, _>(|_handle| {
            let sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                subscribe::WRITE_DONE,
                ro_allow::WRITE,
                buf,
            );

            S::command(
                self.driver_num,
                flash_storage_cmd::WRITE,
                address as u32,
                len as u32,
            )
            .to_result::<(), ErrorCode>()?;

            Ok(sub)
        })?
        .await?;

        Ok(())
    }

    /// Erases an arbitrary number of bytes from the flash memory.
    ///
    /// This method erases `len` bytes from the flash memory starting at the specified `address`.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address to erase from.
    /// * `len` - The number of bytes to erase.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the erase operation is successful.
    /// * `Err(ErrorCode)` if there is an error.
    pub async fn erase(&self, address: usize, len: usize) -> Result<(), ErrorCode> {
        let async_erase_sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::ERASE_DONE);
        S::command(
            self.driver_num,
            flash_storage_cmd::ERASE,
            address as u32,
            len as u32,
        )
        .to_result::<(), ErrorCode>()?;
        async_erase_sub.await.map(|_| Ok(()))?
    }
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

pub mod driver_num {
    pub const IMAGE_PARTITION: u32 = 0x8000_0006;
    pub const STAGING_PARTITION: u32 = 0x8000_0007;
}

mod subscribe {
    /// Read done callback.
    pub const READ_DONE: u32 = 0;
    /// Write done callback.
    pub const WRITE_DONE: u32 = 1;
    /// Erase done callback
    pub const ERASE_DONE: u32 = 2;
}

/// Ids for read-only allow buffers
mod ro_allow {
    /// Setup a buffer to write bytes to the flash storage.
    pub const WRITE: u32 = 0;
}

/// Ids for read-write allow buffers
mod rw_allow {
    /// Setup a buffer to read from the flash storage into.
    pub const READ: u32 = 0;
}

/// Command IDs for flash partition driver capsule
///
/// - `0`: Return Ok(()) if this driver is included on the platform.
/// - `1`: Return flash capacity available to userspace.
/// - `2`: Start a read
/// - `3`: Start a write
/// - `4`: Start an erase
mod flash_storage_cmd {
    pub const EXISTS: u32 = 0;
    pub const CAPACITY: u32 = 1;
    pub const READ: u32 = 2;
    pub const WRITE: u32 = 3;
    pub const ERASE: u32 = 4;
}
