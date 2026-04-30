// Licensed under the Apache-2.0 license

//! This provides the Caliptra capsule that handles syscalls for reading registers.

use caliptra_mcu_romtime::CaliptraSoC;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::TakeCell;
use kernel::{ErrorCode, ProcessId};

/// The driver number for Caliptra commands.
pub const DRIVER_NUM: usize = 0x8000_0011;

mod cmd {
    pub const CALIPTRA_READ: u32 = 1;
    pub const CALIPTRA_SET_REGISTER: u32 = 3;
}

pub mod reg {
    pub const VENDOR_PK_HASH: u32 = 0x260;
}

#[derive(Default)]
pub struct App {
    pub reg_offset: u32,
    pub reg_index: u32,
}

pub struct Caliptra {
    // The underlying Caliptra API SoC interface
    driver: TakeCell<'static, CaliptraSoC>,
    // Per-app state.
    apps: Grant<App, UpcallCount<0>, AllowRoCount<0>, AllowRwCount<0>>,
}

impl Caliptra {
    pub fn new(
        grant: Grant<App, UpcallCount<0>, AllowRoCount<0>, AllowRwCount<0>>,
        driver: &'static mut CaliptraSoC,
    ) -> Caliptra {
        Caliptra {
            driver: TakeCell::new(driver),
            apps: grant,
        }
    }

    fn read_reg(&self, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| match app.reg_offset {
            reg::VENDOR_PK_HASH => self
                .driver
                .map(
                    |driver| match driver.read_vendor_pk_hash().get(app.reg_index as usize) {
                        Some(word) => CommandReturn::success_u32(*word),
                        None => CommandReturn::failure(ErrorCode::INVAL),
                    },
                )
                .ok_or(ErrorCode::RESERVE)
                .unwrap_or_else(CommandReturn::failure),
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }) {
            Ok(ret) => ret,
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        }
    }

    fn set_reg(&self, reg: u32, index: u32, processid: ProcessId) -> CommandReturn {
        if self
            .apps
            .enter(processid, |app, _| {
                app.reg_offset = reg;
                app.reg_index = index;
            })
            .is_err()
        {
            return CommandReturn::failure(ErrorCode::FAIL);
        }
        CommandReturn::success()
    }
}

impl SyscallDriver for Caliptra {
    fn command(
        &self,
        caliptra_cmd: usize,
        arg1: usize,
        arg2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match caliptra_cmd as u32 {
            cmd::CALIPTRA_READ => self.read_reg(processid),
            cmd::CALIPTRA_SET_REGISTER => self.set_reg(arg1 as u32, arg2 as u32, processid),
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
