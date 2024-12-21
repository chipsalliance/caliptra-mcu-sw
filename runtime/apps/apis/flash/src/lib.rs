// Licensed under the Apache-2.0 license

// Flash userspace library

#![no_std]

use libtock_platform as platform;
use libtock_platform::allow_rw::AllowRw;
use libtock_platform::share;
use libtock_platform::AllowRo;
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

pub struct AsyncSpiFlash<const DRIVER_NUM: u32, S: Syscalls, C: Config = DefaultConfig>(S, C);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlashCapacity(pub u32);

/// Represents an asynchronous SPI flash memory interface.
///
/// This struct provides methods to interact with SPI flash memory in an asynchronous manner,
/// allowing for non-blocking read, write, and erase operations.
impl<const DRIVER_NUM: u32, S: Syscalls, C: Config> AsyncSpiFlash<DRIVER_NUM, S, C> {
    /// Checks if the SPI flash exists.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the SPI flash exists.
    /// * `Err(ErrorCode)` if there is an error.
    pub fn exists() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, flash_storage_cmd::EXISTS, 0, 0).to_result()
    }

    /// Gets the capacity of the SPI flash memory that is available to userspace.
    ///
    /// # Returns
    ///
    /// * `Ok(FlashCapacity)` with the capacity of the SPI flash memory.
    /// * `Err(ErrorCode)` if there is an error.
    pub fn get_capacity() -> Result<FlashCapacity, ErrorCode> {
        S::command(DRIVER_NUM, flash_storage_cmd::CAPACITY, 0, 0)
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
    pub async fn read(address: usize, len: usize, buf: &mut [u8]) -> Result<(), ErrorCode> {
        if buf.len() < len {
            return Err(ErrorCode::NoMem);
        }

        let async_read_sub =
            share::scope::<(AllowRw<_, DRIVER_NUM, { rw_allow::READ }>,), _, _>(|handle| {
                let allow_rw = handle.split().0;
                S::allow_rw::<C, DRIVER_NUM, { rw_allow::READ }>(allow_rw, buf)?;

                let sub = TockSubscribe::subscribe::<S>(DRIVER_NUM, subscribe::READ_DONE);
                S::command(
                    DRIVER_NUM,
                    flash_storage_cmd::READ,
                    address as u32,
                    len as u32,
                )
                .to_result::<(), ErrorCode>()?;

                Ok(sub)
            })?;

        async_read_sub.await.map(|_| Ok(()))?
    }

    pub async fn write(address: usize, len: usize, buf: &[u8]) -> Result<(), ErrorCode> {
        let async_write_sub =
            share::scope::<(AllowRo<_, DRIVER_NUM, { ro_allow::WRITE }>,), _, _>(|handle| {
                let allow_ro = handle.split().0;
                S::allow_ro::<C, DRIVER_NUM, { ro_allow::WRITE }>(allow_ro, buf)?;

                let sub = TockSubscribe::subscribe::<S>(DRIVER_NUM, subscribe::WRITE_DONE);

                S::command(
                    DRIVER_NUM,
                    flash_storage_cmd::WRITE,
                    address as u32,
                    len as u32,
                )
                .to_result::<(), ErrorCode>()?;

                Ok(sub)
            })?;

        async_write_sub.await.map(|_| Ok(()))?
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
    pub async fn erase(address: usize, len: usize) -> Result<(), ErrorCode> {
        let async_erase_sub = TockSubscribe::subscribe::<S>(DRIVER_NUM, subscribe::ERASE_DONE);
        S::command(
            DRIVER_NUM,
            flash_storage_cmd::ERASE,
            address as u32,
            len as u32,
        )
        .to_result::<(), ErrorCode>()?;

        async_erase_sub.await.map(|_| Ok(()))?
    }
}

/// System call configuration trait for `AsyncSpiFlash`.
pub trait Config:
    platform::allow_ro::Config + platform::allow_rw::Config + platform::subscribe::Config
{
}
impl<T: platform::allow_ro::Config + platform::allow_rw::Config + platform::subscribe::Config>
    Config for T
{
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
