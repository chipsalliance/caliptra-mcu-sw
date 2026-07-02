// Licensed under the Apache-2.0 license

//! Userspace wrapper for the read-only DOT flash capsule.

use crate::DefaultSyscalls;
use caliptra_mcu_libtock_platform::{share, AllowRw, DefaultConfig, ErrorCode, Syscalls};
use core::marker::PhantomData;

pub const DRIVER_NUM: u32 = 0x9000_4000;

pub struct DotFlash<S: Syscalls = DefaultSyscalls> {
    syscall: PhantomData<S>,
}

impl<S: Syscalls> DotFlash<S> {
    pub fn new() -> Self {
        Self {
            syscall: PhantomData,
        }
    }

    pub fn read(&self, offset: usize, buffer: &mut [u8]) -> Result<(), ErrorCode> {
        let len = buffer.len() as u32;
        share::scope::<AllowRw<S, DRIVER_NUM, { rw_allow::READ_BUFFER }>, _, _>(|handle| {
            S::allow_rw::<DefaultConfig, DRIVER_NUM, { rw_allow::READ_BUFFER }>(handle, buffer)?;
            S::command(DRIVER_NUM, cmd::READ, offset as u32, len).to_result::<(), ErrorCode>()
        })
    }
}

impl<S: Syscalls> Default for DotFlash<S> {
    fn default() -> Self {
        Self::new()
    }
}

mod cmd {
    pub const READ: u32 = 1;
}

mod rw_allow {
    pub const READ_BUFFER: u32 = 0;
}
