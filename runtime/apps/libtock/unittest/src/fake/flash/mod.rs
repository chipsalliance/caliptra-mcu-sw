use crate::fake::SyscallDriver;
use crate::{DriverInfo, DriverShareRef};
use crate::{RoAllowBuffer, RwAllowBuffer};
use libtock_platform::{CommandReturn, ErrorCode};
use std::cell::RefCell;

pub struct FakeFlashDriver {
    exists: RefCell<bool>,
    capacity: RefCell<u32>,
    chunk_size: RefCell<usize>,
    read_buffer: RefCell<RwAllowBuffer>,
    write_buffer: RefCell<RoAllowBuffer>,
    share_ref: DriverShareRef,
    flash_content: RefCell<Vec<u8>>,
}

impl Default for FakeFlashDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeFlashDriver {
    pub fn new() -> Self {
        Self {
            exists: RefCell::new(true),
            capacity: RefCell::new(0),
            chunk_size: RefCell::new(256), // Default chunk size
            read_buffer: Default::default(),
            write_buffer: Default::default(),
            share_ref: Default::default(),
            flash_content: Default::default(),
        }
    }

    /// Set the capacity of the flash
    pub fn set_capacity(&self, capacity: u32) {
        *self.capacity.borrow_mut() = capacity;
    }

    /// Set the chunk size for read/write operations
    pub fn set_chunk_size(&self, chunk_size: usize) {
        *self.chunk_size.borrow_mut() = chunk_size;
    }

    /// Set the flash content
    pub fn set_flash_content(&self, content: Vec<u8>) {
        self.flash_content.replace(content);
    }
}

impl SyscallDriver for FakeFlashDriver {
    fn info(&self) -> DriverInfo {
        DriverInfo::new(driver_num::IMAGE_PARTITION).upcall_count(3)
    }

    fn register(&self, share_ref: DriverShareRef) {
        self.share_ref.replace(share_ref);
    }

    fn command(&self, command_num: u32, arg0: u32, arg1: u32) -> CommandReturn {
        match command_num {
            flash_storage_cmd::EXISTS => {
                if *self.exists.borrow() {
                    crate::command_return::success()
                } else {
                    crate::command_return::failure(ErrorCode::NoDevice)
                }
            }
            flash_storage_cmd::GET_CAPACITY => {
                crate::command_return::success_u32(*self.capacity.borrow())
            }
            flash_storage_cmd::GET_CHUNK_SIZE => {
                crate::command_return::success_u32(*self.chunk_size.borrow() as u32)
            }
            flash_storage_cmd::READ => {
                let address = arg0 as usize;
                let len = arg1 as usize;
                if address + len > self.flash_content.borrow().len() {
                    return crate::command_return::failure(ErrorCode::NoMem);
                }

                let data = &self.flash_content.borrow()[address..];
                // Copy data from flash content to read buffer
                self.read_buffer.borrow_mut()[..len].copy_from_slice(&data[..len]);
                // Schedule upcall for read completion
                self.share_ref
                    .schedule_upcall(subscribe::READ_DONE, (len as u32, 0, 0))
                    .expect("Failed to schedule READ_DONE upcall");
                crate::command_return::success()
            }
            flash_storage_cmd::WRITE => {
                // Schedule upcall for write completion
                self.share_ref
                    .schedule_upcall(subscribe::WRITE_DONE, (arg1, 0, 0))
                    .expect("Failed to schedule WRITE_DONE upcall");
                crate::command_return::success()
            }
            flash_storage_cmd::ERASE => {
                // Simulate erase completion
                let len = arg1 as usize;
                self.share_ref
                    .schedule_upcall(subscribe::ERASE_DONE, (len as u32, 0, 0))
                    .expect("Failed to schedule ERASE_DONE upcall");
                crate::command_return::success()
            }
            _ => crate::command_return::failure(ErrorCode::Invalid),
        }
    }

    fn allow_readwrite(
        &self,
        allow_num: u32,
        buffer: RwAllowBuffer,
    ) -> Result<RwAllowBuffer, (RwAllowBuffer, ErrorCode)> {
        if allow_num == rw_allow::READ {
            Ok(self.read_buffer.replace(buffer))
        } else {
            Err((buffer, ErrorCode::Invalid))
        }
    }

    fn allow_readonly(
        &self,
        allow_num: u32,
        buffer: RoAllowBuffer,
    ) -> Result<RoAllowBuffer, (RoAllowBuffer, ErrorCode)> {
        if allow_num == ro_allow::WRITE {
            Ok(self.write_buffer.replace(buffer))
        } else {
            Err((buffer, ErrorCode::Invalid))
        }
    }
}

// -----------------------------------------------------------------------------
// Constants and Command IDs
// -----------------------------------------------------------------------------

pub mod driver_num {
    pub const IMAGE_PARTITION: u32 = 0x8000_0006;
}

mod flash_storage_cmd {
    pub const EXISTS: u32 = 0;
    pub const GET_CAPACITY: u32 = 1;
    pub const READ: u32 = 2;
    pub const WRITE: u32 = 3;
    pub const ERASE: u32 = 4;
    pub const GET_CHUNK_SIZE: u32 = 5;
}

mod subscribe {
    pub const READ_DONE: u32 = 0;
    pub const WRITE_DONE: u32 = 1;
    pub const ERASE_DONE: u32 = 2;
}

mod ro_allow {
    pub const WRITE: u32 = 0;
}

mod rw_allow {
    pub const READ: u32 = 0;
}
