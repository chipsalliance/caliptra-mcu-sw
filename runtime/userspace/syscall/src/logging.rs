// Licensed under the Apache-2.0 license

// Userspace logging syscall API

use crate::DefaultSyscalls;
use core::marker::PhantomData;
use libtock_platform::{share, DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

pub struct LoggingSyscall<S: Syscalls = DefaultSyscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> LoggingSyscall<S> {
    pub fn new(driver_num: u32) -> Self {
        Self {
            syscall: PhantomData,
            driver_num,
        }
    }

    pub async fn append_entry(&self, entry: &[u8]) -> Result<(), ErrorCode> {
        let result = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_ro::<S, DefaultConfig>(
                self.driver_num,
                subscribe::APPEND_DONE,
                ro_allow::APPEND,
                entry,
            );
            if let Err(e) = S::command(self.driver_num, logging_cmd::APPEND, entry.len() as u32, 0)
                .to_result::<(), ErrorCode>()
            {
                S::unallow_ro(self.driver_num, ro_allow::APPEND);
                sub.cancel();
                Err(e)?;
            }
            Ok(TockSubscribe::subscribe_finish(sub))
        })?
        .await;
        S::unallow_ro(self.driver_num, ro_allow::APPEND);
        result.map(|_| ())
    }

    pub async fn sync(&self) -> Result<(), ErrorCode> {
        let sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::SYNC_DONE);
        S::command(self.driver_num, logging_cmd::SYNC, 0, 0).to_result::<(), ErrorCode>()?;
        sub.await.map(|_| Ok(()))?
    }

    pub async fn clear(&self) -> Result<(), ErrorCode> {
        let sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::ERASE_DONE);
        S::command(self.driver_num, logging_cmd::ERASE, 0, 0).to_result::<(), ErrorCode>()?;
        sub.await.map(|_| Ok(()))?
    }

    pub fn get_capacity(&self) -> Result<usize, ErrorCode> {
        S::command(self.driver_num, logging_cmd::GET_CAP, 0, 0)
            .to_result()
            .map(|x: u32| x as usize)
    }

    pub async fn read_entry(
        &self,
        //offset: usize,
        buffer: &mut [u8],
    ) -> Result<usize, ErrorCode> {
        let result = share::scope::<(), _, _>(|_handle| {
            let mut sub = TockSubscribe::subscribe_allow_rw::<S, DefaultConfig>(
                self.driver_num,
                subscribe::READ_DONE,
                rw_allow::READ,
                buffer,
            );
            if let Err(e) = S::command(self.driver_num, logging_cmd::READ, buffer.len() as u32, 0)
                .to_result::<(), ErrorCode>()
            {
                S::unallow_rw(self.driver_num, rw_allow::READ);
                sub.cancel();
                Err(e)?;
            }
            Ok(TockSubscribe::subscribe_finish(sub))
        })?
        .await;
        S::unallow_rw(self.driver_num, rw_allow::READ);
        result.map(|(len, _, _)| len as usize)
    }
}

mod subscribe {
    pub const READ_DONE: u32 = 0;
    pub const SEEK_DONE: u32 = 1;
    pub const APPEND_DONE: u32 = 2;
    pub const SYNC_DONE: u32 = 3;
    pub const ERASE_DONE: u32 = 4;
}

mod ro_allow {
    pub const APPEND: u32 = 0;
}

mod rw_allow {
    pub const READ: u32 = 0;
}

mod logging_cmd {
    pub const READ: u32 = 1;
    pub const APPEND: u32 = 2;
    pub const SEEK: u32 = 3;
    pub const SYNC: u32 = 4;
    pub const ERASE: u32 = 5;
    pub const GET_CAP: u32 = 6;
}
