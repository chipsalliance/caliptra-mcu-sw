#![no_std]

use core::cell::Cell;
use libtock_platform as platform;
use libtock_platform::allow_rw::AllowRw;
use libtock_platform::share;
use libtock_platform::subscribe::Subscribe;
use libtock_platform::AllowRo;
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

/// A structure representing an asynchronous SPI flash memory interface.
pub struct AsyncSpiFlash<S: Syscalls, C: Config = DefaultConfig>(S, C);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlashCapacity(pub u32);

/// Represents an asynchronous SPI flash memory interface.
///
/// This struct provides methods to interact with SPI flash memory in an asynchronous manner,
/// allowing for non-blocking read, write, and erase operations.
impl<S: Syscalls, C: Config> AsyncSpiFlash<S, C> {
    /// Checks if the SPI flash exists.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the SPI flash exists.
    /// * `Err(ErrorCode)` if there is an error.
    pub fn exists() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, flash_storage_cmd::EXISTS, 0, 0).to_result()
    }

    /// Returns the capacity of the SPI flash.
    pub fn get_capacity() -> Result<FlashCapacity, ErrorCode> {
        S::command(DRIVER_NUM, flash_storage_cmd::CAPACITY, 0, 0)
            .to_result()
            .map(FlashCapacity)
    }

    pub fn read_sync (address: usize, len: usize, buf: &mut [u8]) -> Result<(), ErrorCode> {
        if buf.len() < len {
            return Err(ErrorCode::NoMem);
        }

        let called: Cell<Option<(u32, u32, u32)>> = Cell::new(None);
        share::scope::<
            (
                AllowRw<_, DRIVER_NUM, { rw_allow::READ }>,
                Subscribe<_, DRIVER_NUM, { subscribe::READ_DONE }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_rw, subscribe) = handle.split();
            S::allow_rw::<C, DRIVER_NUM, { rw_allow::READ }>(allow_rw, buf)?;
            S::subscribe::<_, _, C, DRIVER_NUM, { subscribe::READ_DONE }>(subscribe, &called)?;

            S::command(DRIVER_NUM, flash_storage_cmd::READ, address as u32, len as u32)
                .to_result::<(), ErrorCode>()?;

            loop {
                S::yield_wait();

                if let Some((r0, _,  _)) = called.get() {
                    assert_eq!(r0, len as u32);
                    return Ok(());
                }
            }
        })
    }

    pub fn write_sync(address: usize, len: usize, buf: &[u8]) -> Result<(), ErrorCode> {
        if buf.len() < len {
            return Err(ErrorCode::NoMem);
        }

        let called: Cell<Option<(u32, u32, u32)>> = Cell::new(None);
        share::scope::<
            (
                AllowRo<_, DRIVER_NUM, { ro_allow::WRITE }>,
                Subscribe<_, DRIVER_NUM, { subscribe::WRITE_DONE }>,
            ),
            _,
            _,
        >(|handle| {
            let (allow_ro, subscribe) = handle.split();
            S::allow_ro::<C, DRIVER_NUM, { ro_allow::WRITE }>(allow_ro, buf)?;
            S::subscribe::<_, _, C, DRIVER_NUM, { subscribe::WRITE_DONE }>(subscribe, &called)?;

            S::command(DRIVER_NUM, flash_storage_cmd::WRITE, address as u32, len as u32)
                .to_result::<(), ErrorCode>()?;

            loop {
                S::yield_wait();

                if let Some((r0, _,  _)) = called.get() {
                    assert_eq!(r0, len as u32);
                    return Ok(());
                }
            }
        })
    }


    pub fn erase_sync (address: usize, len: usize) -> Result<(), ErrorCode> {
        let called: Cell<Option<(u32, u32, u32)>> = Cell::new(None);
        share::scope::<
            Subscribe<_, DRIVER_NUM, { subscribe::ERASE_DONE }>,
            _,
            _,
        >(|handle| {
            let subscribe = handle;
            S::subscribe::<_, _, C, DRIVER_NUM, { subscribe::ERASE_DONE }>(subscribe, &called)?;

            S::command(DRIVER_NUM, flash_storage_cmd::ERASE, address as u32, len as u32)
                .to_result::<(), ErrorCode>()?;

            loop {
                S::yield_wait();

                if let Some((r0, _,  _)) = called.get() {
                    assert_eq!(r0, len as u32);
                    return Ok(());
                }
            }
        })
    }

    /// Reads an arbitrary number of bytes from the flash memory.
    ///
    /// This method reads `len` bytes from the flash memory starting at the specified `address`
    /// and stores them in the provided `buf`.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address to read from.
    /// * `len` - The number of bytes to read.
    /// * `buf` - The buffer to store the read bytes.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the read operation is successful.
    /// * `Err(ErrorCode)` if there is an error.
    pub async fn read(_address: usize, _len: usize, _buf: &mut [u8]) -> Result<(), ErrorCode> {
        todo!()
    }

    /// Writes an arbitrary number of bytes to the flash memory.
    ///
    /// This method writes the bytes from the provided `buf` to the flash memory starting at the
    /// specified `address`.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address to write to.
    /// * `buf` - The buffer containing the bytes to write.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the write operation is successful.
    /// * `Err(ErrorCode)` if there is an error.
    pub async fn write(_address: usize, _len: usize, _buf: &[u8]) -> Result<(), ErrorCode> {
        todo!()
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
        // Issue the erase command to the flash storage driver
        let sub = TockSubscribe::subscribe::<S>(DRIVER_NUM, subscribe::ERASE_DONE);
        S::command(
            DRIVER_NUM,
            flash_storage_cmd::ERASE,
            address as u32,
            len as u32,
        )
        .to_result()
        .map(|_when: u32| ())?;

        sub.await.map(|_| ())
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
const DRIVER_NUM: u32 = 0x5000_0006;

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

// Command IDs for flash partition driver capsule
/*
/// - `0`: Return Ok(()) if this driver is included on the platform.
/// - `1`: Return the number of bytes available to userspace.
/// - `2`: Start a read
/// - `3`: Start a write
/// - `4`: Start an erase
*/
mod flash_storage_cmd {
    pub const EXISTS: u32 = 0;
    pub const CAPACITY: u32 = 1;
    pub const READ: u32 = 2;
    pub const WRITE: u32 = 3;
    pub const ERASE: u32 = 4;
}
