// Licensed under the Apache-2.0 license

#![no_std]

use core::cell::Cell;
use libtock_platform as platform;
use libtock_platform::allow_rw::AllowRw;
use libtock_platform::share;
use libtock_platform::subscribe::Subscribe;
use libtock_platform::AllowRo;
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};

pub struct SpiFlash<const DRIVER_NUM: u32, S: Syscalls, C: Config = DefaultConfig>(S, C);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlashCapacity(pub u32);

/// Represents SPI flash memory userland interface.
///
/// This struct provides methods for checking the existence of the SPI flash, getting its capacity,
/// reading from, writing to, and erasing the flash memory. It supports both synchronous and asynchronous
/// operations.
///
/// # Type Parameters
///
/// * `S` - A type that implements the `Syscalls` trait.
/// * `C` - A type that implements the `Config` trait.
///
/// # Methods
///
/// * `exists` - Checks if the SPI flash exists.
/// * `get_capacity` - Gets the capacity of the SPI flash.
/// * `read_sync` - Reads data synchronously from the SPI flash.
/// * `write_sync` - Writes data synchronously to the SPI flash.
/// * `erase_sync` - Erases data synchronously from the SPI flash.
/// * `read` - Reads data asynchronously from the SPI flash.
/// * `write` - Writes data asynchronously to the SPI flash.
/// * `erase` - Erases data asynchronously from the SPI flash.
impl<const DRIVER_NUM: u32, S: Syscalls, C: Config> SpiFlash<DRIVER_NUM, S, C> {
    pub fn exists() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, flash_storage_cmd::EXISTS, 0, 0).to_result()
    }

    pub fn get_capacity() -> Result<FlashCapacity, ErrorCode> {
        S::command(DRIVER_NUM, flash_storage_cmd::CAPACITY, 0, 0)
            .to_result()
            .map(FlashCapacity)
    }

    pub fn read_sync(address: usize, len: usize, buf: &mut [u8]) -> Result<(), ErrorCode> {
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

            S::command(
                DRIVER_NUM,
                flash_storage_cmd::READ,
                address as u32,
                len as u32,
            )
            .to_result::<(), ErrorCode>()?;

            loop {
                S::yield_wait();

                if let Some((r0, _, _)) = called.get() {
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

            S::command(
                DRIVER_NUM,
                flash_storage_cmd::WRITE,
                address as u32,
                len as u32,
            )
            .to_result::<(), ErrorCode>()?;

            loop {
                S::yield_wait();

                if let Some((r0, _, _)) = called.get() {
                    assert_eq!(r0, len as u32);
                    return Ok(());
                }
            }
        })
    }

    pub fn erase_sync(address: usize, len: usize) -> Result<(), ErrorCode> {
        let called: Cell<Option<(u32, u32, u32)>> = Cell::new(None);
        share::scope::<Subscribe<_, DRIVER_NUM, { subscribe::ERASE_DONE }>, _, _>(|handle| {
            let subscribe = handle;
            S::subscribe::<_, _, C, DRIVER_NUM, { subscribe::ERASE_DONE }>(subscribe, &called)?;

            S::command(
                DRIVER_NUM,
                flash_storage_cmd::ERASE,
                address as u32,
                len as u32,
            )
            .to_result::<(), ErrorCode>()?;

            loop {
                S::yield_wait();

                if let Some((r0, _, _)) = called.get() {
                    assert_eq!(r0, len as u32);
                    return Ok(());
                }
            }
        })
    }

    pub async fn read(_address: usize, _len: usize, _buf: &mut [u8]) -> Result<(), ErrorCode> {
        todo!()
    }

    pub async fn write(_address: usize, _len: usize, _buf: &[u8]) -> Result<(), ErrorCode> {
        todo!()
    }

    pub async fn erase(_address: usize, _len: usize) -> Result<(), ErrorCode> {
        todo!()
    }
}

/// System call configuration trait for `SpiFlash`.
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
//const DRIVER_NUM: u32 = 0x8000_0006;

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
