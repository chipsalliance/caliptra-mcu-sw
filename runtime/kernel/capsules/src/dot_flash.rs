// Licensed under the Apache-2.0 license

//! Read-only capsule for platform DOT flash storage.
//!
//! The DOT recovery flow stores the authenticated DOT_BLOB in platform-owned
//! DOT flash. Userspace command handlers need a narrow read-only path to return
//! that blob to an external requester without exposing general flash/MMIO
//! access.

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{WriteableProcessBuffer, WriteableProcessSlice};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};
use tock_registers::interfaces::Readable;
use tock_registers::registers::ReadOnly;

pub const DRIVER_NUM: usize = 0x9000_4000;

#[derive(Default)]
pub struct App {}

pub struct DotFlash {
    storage: &'static [ReadOnly<u8>],
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
}

impl DotFlash {
    pub fn new(
        storage: &'static [ReadOnly<u8>],
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Self {
        Self {
            storage,
            apps: grant,
        }
    }

    fn read(&self, offset: usize, len: usize, processid: ProcessId) -> Result<(), ErrorCode> {
        let end = offset.checked_add(len).ok_or(ErrorCode::INVAL)?;
        if end > self.storage.len() {
            return Err(ErrorCode::INVAL);
        }

        self.apps.enter(processid, |_app, kernel_data| {
            kernel_data
                .get_readwrite_processbuffer(rw_allow::READ_BUFFER)
                .map_err(|_| ErrorCode::FAIL)
                .and_then(|rw_buffer| {
                    rw_buffer
                        .mut_enter(|app_buffer| self.copy_read(offset, len, app_buffer))
                        .map_err(|_| ErrorCode::FAIL)?
                })
        })?
    }

    fn copy_read(
        &self,
        offset: usize,
        len: usize,
        app_buffer: &WriteableProcessSlice,
    ) -> Result<(), ErrorCode> {
        if app_buffer.len() < len {
            return Err(ErrorCode::SIZE);
        }
        for i in 0..len {
            let byte = self.storage[offset + i].get();
            app_buffer
                .get(i..i + 1)
                .ok_or(ErrorCode::INVAL)?
                .copy_from_slice(core::slice::from_ref(&byte));
        }
        Ok(())
    }
}

impl SyscallDriver for DotFlash {
    fn command(&self, cmd: usize, arg1: usize, arg2: usize, processid: ProcessId) -> CommandReturn {
        let exec_result = match cmd as u32 {
            cmd::EXISTS => Ok(()),
            cmd::READ => self.read(arg1, arg2, processid),
            _ => Err(ErrorCode::NOSUPPORT),
        };
        match exec_result {
            Ok(()) => CommandReturn::success(),
            Err(e) => CommandReturn::failure(e),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}

mod cmd {
    pub const EXISTS: u32 = 0;
    pub const READ: u32 = 1;
}

mod upcall {
    pub const COUNT: u8 = 0;
}

mod ro_allow {
    pub const COUNT: u8 = 0;
}

mod rw_allow {
    pub const READ_BUFFER: usize = 0;
    pub const COUNT: u8 = 1;
}
