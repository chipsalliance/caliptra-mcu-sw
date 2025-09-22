// Licensed under the Apache-2.0 license

//! This provides the MCI capsule that calls the underlying MCI driver

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

/// The driver number for Caliptra MCI commands.
pub const DRIVER_NUM: usize = 0xB000_0000;

mod cmd {
    pub const MCI_READ: u32 = 1;
    pub const MCI_WRITE: u32 = 2;
    pub const MCI_SET_REGISTER: u32 = 3;
    pub const MCI_TRIGGER_WARM_RESET: u32 = 4;
}

mod mci_reg {
    pub const RESET_REASON: u32 = 0x38;
    pub const WDT_TIMER1_EN: u32 = 0xb0;
    pub const NOTIF0_INTR_TRIG_R: u32 = 0x1034;
}

#[derive(Default)]
pub struct App {
    pub reg_offset: u32,
    pub reg_index: u32,
}

pub struct Mci {
    driver: &'static romtime::Mci,
    // Per-app state.
    apps: Grant<App, UpcallCount<0>, AllowRoCount<0>, AllowRwCount<0>>,
}

impl Mci {
    pub fn new(
        driver: &'static romtime::Mci,
        grant: Grant<App, UpcallCount<0>, AllowRoCount<0>, AllowRwCount<0>>,
    ) -> Mci {
        Mci {
            driver,
            apps: grant,
        }
    }

    fn read_reg(&self, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| match app.reg_offset {
            mci_reg::RESET_REASON => CommandReturn::success_u32(self.driver.reset_reason()),
            mci_reg::WDT_TIMER1_EN => CommandReturn::success_u32(self.driver.read_wdt_timer1_en()),
            mci_reg::NOTIF0_INTR_TRIG_R => {
                CommandReturn::success_u32(self.driver.read_notif0_intr_trig_r())
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }) {
            Ok(ret) => ret,
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        }
    }

    fn write_reg(&self, value: u32, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| match app.reg_offset {
            mci_reg::WDT_TIMER1_EN => {
                self.driver.write_wdt_timer1_en(value);
                CommandReturn::success()
            }
            mci_reg::NOTIF0_INTR_TRIG_R => {
                self.driver.write_notif0_intr_trig_r(value);
                CommandReturn::success()
            }
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

/// Provide an interface for userland.
impl SyscallDriver for Mci {
    fn command(
        &self,
        mci_cmd: usize,
        arg1: usize,
        arg2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match mci_cmd as u32 {
            cmd::MCI_READ => self.read_reg(processid),
            cmd::MCI_WRITE => self.write_reg(arg1 as u32, processid),
            cmd::MCI_SET_REGISTER => self.set_reg(arg1 as u32, arg2 as u32, processid),
            cmd::MCI_TRIGGER_WARM_RESET => {
                self.driver.trigger_warm_reset();
                CommandReturn::success()
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
