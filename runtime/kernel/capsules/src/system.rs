// Licensed under the Apache-2.0 license

//! This provides the capsule for Platform specific system utilities.

use core::cell::RefCell;

use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

pub const DRIVER_NUM: usize = 0xC000_0000;

mod cmd {
    pub const EXIT: u32 = 1;
}

pub struct System<'a, E: romtime::Exit> {
    exiter: RefCell<&'a mut E>,
}

impl<'a, E: romtime::Exit> System<'a, E> {
    pub fn new(exiter: &'a mut E) -> System<'a, E> {
        System {
            exiter: RefCell::new(exiter),
        }
    }
}

/// Provide an interface for userland.
impl<E: romtime::Exit> SyscallDriver for System<'_, E> {
    fn command(
        &self,
        cmd: usize,
        arg1: usize,
        _arg2: usize,
        _processid: ProcessId,
    ) -> CommandReturn {
        match cmd as u32 {
            cmd::EXIT => {
                self.exiter.borrow_mut().exit(arg1 as u32);
                CommandReturn::success()
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, _processid: ProcessId) -> Result<(), kernel::process::Error> {
        Ok(())
    }
}
