// Licensed under the Apache-2.0 license

use crate::DefaultSyscalls;
use core::marker::PhantomData;
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

pub struct MboxSram<S: Syscalls = DefaultSyscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> MboxSram<S> {
    pub fn new(driver_num: u32) -> Self {
        Self {
            syscall: PhantomData,
            driver_num,
        }
    }

    pub async fn write(&self, offset: usize, buffer: &[u8]) -> Result<(), ErrorCode> {
        let res = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                upcall::DONE,
                ro_allow::WRITE_BUFFER,
                buffer,
            );

            // Issue the command to the kernel
            match S::command(self.driver_num, cmd::MEMORY_WRITE, offset as u32, 0)
                .to_result::<(), ErrorCode>()
            {
                Ok(()) => Ok(TockSubscribe::subscribe_finish(sub)),
                Err(err) => {
                    S::unallow_ro(self.driver_num, ro_allow::WRITE_BUFFER);
                    sub.cancel();
                    Err(err)
                }
            }
        })?
        .await;
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn read(&self, offset: usize, buffer: &mut [u8]) -> Result<(), ErrorCode> {
        let res = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                upcall::DONE,
                rw_allow::READ_BUFFER,
                buffer,
            );

            // Issue the command to the kernel
            match S::command(self.driver_num, cmd::MEMORY_READ, offset as u32, 0)
                .to_result::<(), ErrorCode>()
            {
                Ok(()) => Ok(TockSubscribe::subscribe_finish(sub)),
                Err(err) => {
                    S::unallow_rw(self.driver_num, rw_allow::READ_BUFFER);
                    sub.cancel();
                    Err(err)
                }
            }
        })?
        .await;
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn acquire_lock(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::ACQUIRE_LOCK, 0, 0).to_result::<(), ErrorCode>()
    }

    pub fn release_lock(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::RELEASE_LOCK, 0, 0).to_result::<(), ErrorCode>()
    }
}

pub const DRIVER_NUM_MCU_MBOX0_SRAM: u32 = 0x9000_3000;
pub const DRIVER_NUM_MCU_MBOX1_SRAM: u32 = 0x9000_3001;

mod cmd {
    pub const MEMORY_READ: u32 = 1;
    pub const MEMORY_WRITE: u32 = 2;
    pub const ACQUIRE_LOCK: u32 = 3;
    pub const RELEASE_LOCK: u32 = 4;
}

mod upcall {
    pub const DONE: u32 = 0;
}

/// Ids for read-only allow buffers
mod ro_allow {
    pub const WRITE_BUFFER: u32 = 0;
}

/// Ids for read-write allow buffers
mod rw_allow {
    pub const READ_BUFFER: u32 = 0;
}
