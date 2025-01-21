use crate::fake::SyscallDriver;
use crate::{DriverInfo, DriverShareRef};
use crate::{RoAllowBuffer, RwAllowBuffer};
use libtock_platform::{CommandReturn, ErrorCode};
use std::cell::RefCell;

pub struct FakeDMADriver {
    byte_count: RefCell<usize>,
    src_addr: RefCell<Option<u64>>,
    dest_addr: RefCell<Option<u64>>,
    last_ro_buffer: RefCell<RoAllowBuffer>,
    share_ref: DriverShareRef,
    memory: RefCell<Vec<u8>>,
}
impl Default for FakeDMADriver {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeDMADriver {
    pub fn new() -> Self {
        Self {
            byte_count: RefCell::new(0),
            src_addr: RefCell::new(None),
            dest_addr: RefCell::new(None),
            last_ro_buffer: Default::default(),
            share_ref: Default::default(),
            memory: RefCell::new(Vec::new()),
        }
    }

    pub fn set_memory_size(&self, size: usize) {
        self.memory.borrow_mut().resize(size, 0);
    }

    pub fn read_memory(&self, addr: u64, len: usize) -> Vec<u8> {
        let memory = self.memory.borrow();
        memory[addr as usize..(addr as usize + len)].to_vec()
    }

    /// Get the current byte count for the transfer
    pub fn get_byte_count(&self) -> usize {
        *self.byte_count.borrow()
    }

    /// Get the source address for the transfer
    pub fn get_src_addr(&self) -> Option<u64> {
        *self.src_addr.borrow()
    }

    /// Get the destination address for the transfer
    pub fn get_dest_addr(&self) -> Option<u64> {
        *self.dest_addr.borrow()
    }
}

impl SyscallDriver for FakeDMADriver {
    fn info(&self) -> DriverInfo {
        DriverInfo::new(DMA_DRIVER_NUM).upcall_count(1)
    }

    fn register(&self, share_ref: DriverShareRef) {
        self.share_ref.replace(share_ref);
    }

    fn command(&self, command_num: u32, arg0: u32, arg1: u32) -> CommandReturn {
        match command_num {
            dma_cmd::SET_BYTE_XFER_COUNT => {
                *self.byte_count.borrow_mut() = arg0 as usize;
                crate::command_return::success()
            }
            dma_cmd::SET_SRC_ADDR => {
                let addr = ((arg1 as u64) << 32) | (arg0 as u64);
                *self.src_addr.borrow_mut() = Some(addr);
                crate::command_return::success()
            }
            dma_cmd::SET_DEST_ADDR => {
                let addr = ((arg1 as u64) << 32) | (arg0 as u64);
                *self.dest_addr.borrow_mut() = Some(addr);
                crate::command_return::success()
            }
            dma_cmd::XFER_LOCAL_TO_AXI => {
                let dest_addr = self
                    .dest_addr
                    .borrow()
                    .expect("Destination address not set");
                let byte_count = *self.byte_count.borrow();
                let mut dest_buffer = self.memory.borrow_mut();
                if dest_buffer.len() < dest_addr as usize + byte_count {
                    dest_buffer.resize(dest_addr as usize + byte_count, 0);
                }
                dest_buffer[dest_addr as usize..(dest_addr as usize + byte_count)]
                    .copy_from_slice(self.last_ro_buffer.borrow().as_ref());

                self.share_ref
                    .schedule_upcall(dma_subscribe::XFER_DONE, (0, 0, 0))
                    .expect("Unable to schedule upcall");
                crate::command_return::success()
            }
            dma_cmd::XFER_AXI_TO_AXI => {
                // Not supported at the moment
                // Simulate the transfer completion by scheduling an upcall
                self.share_ref
                    .schedule_upcall(dma_subscribe::XFER_DONE, (0, 0, 0))
                    .expect("Unable to schedule upcall");
                crate::command_return::success()
            }
            _ => crate::command_return::failure(ErrorCode::Invalid),
        }
    }

    fn allow_readonly(
        &self,
        allow_num: u32,
        buffer: RoAllowBuffer,
    ) -> Result<RoAllowBuffer, (RoAllowBuffer, ErrorCode)> {
        if allow_num == dma_ro_buffer::LOCAL_SOURCE {
            Ok(self.last_ro_buffer.replace(buffer))
        } else {
            Err((buffer, ErrorCode::Invalid))
        }
    }

    fn allow_readwrite(
        &self,
        _allow_num: u32,
        _buffer: RwAllowBuffer,
    ) -> Result<RwAllowBuffer, (RwAllowBuffer, ErrorCode)> {
        Err((Default::default(), ErrorCode::Invalid))
    }
}

// DMA constants
pub const DMA_DRIVER_NUM: u32 = 0x8000_0008;

mod dma_cmd {
    pub const SET_BYTE_XFER_COUNT: u32 = 0;
    pub const SET_SRC_ADDR: u32 = 1;
    pub const SET_DEST_ADDR: u32 = 2;
    pub const XFER_AXI_TO_AXI: u32 = 3;
    pub const XFER_LOCAL_TO_AXI: u32 = 4;
}

mod dma_ro_buffer {
    pub const LOCAL_SOURCE: u32 = 0;
}

mod dma_subscribe {
    pub const XFER_DONE: u32 = 0;
}
