// Licensed under the Apache-2.0 license

//! This provides the OTP capsule that calls the underlying OTP driver

use caliptra_mcu_registers_generated::fuses::OTP_CPTRA_CORE_RUNTIME_SVN;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

/// The driver number for Caliptra OTP commands.
pub const DRIVER_NUM: usize = 0xD000_0000;

pub mod cmd {
    pub const OTP_READ: u32 = 1;
    pub const OTP_WRITE: u32 = 2;
    pub const OTP_SET_REGISTER: u32 = 3;
}

pub mod reg {
    pub const LOCK_TOTAL_HEKS: u32 = 0;
    pub const LOCK_HEK_PROD_0: u32 = 1;
    pub const LOCK_HEK_PROD_1: u32 = 2;
    pub const LOCK_HEK_PROD_2: u32 = 3;
    pub const LOCK_HEK_PROD_3: u32 = 4;
    pub const LOCK_HEK_PROD_4: u32 = 5;
    pub const LOCK_HEK_PROD_5: u32 = 6;
    pub const LOCK_HEK_PROD_6: u32 = 7;
    pub const LOCK_HEK_PROD_7: u32 = 8;

    pub const LOCK_HEK_PROD_ALL: [u32; 8] = [
        LOCK_HEK_PROD_0,
        LOCK_HEK_PROD_1,
        LOCK_HEK_PROD_2,
        LOCK_HEK_PROD_3,
        LOCK_HEK_PROD_4,
        LOCK_HEK_PROD_5,
        LOCK_HEK_PROD_6,
        LOCK_HEK_PROD_7,
    ];

    pub const CALIPTRA_FW_SVN: u32 = 9;
}

#[derive(Default)]
pub struct App {
    pub reg_offset: u32,
    pub reg_index: u32,
}

pub struct Otp {
    driver: &'static caliptra_mcu_romtime::Otp,
    total_heks: u32,
    // Per-app state.
    apps: Grant<App, UpcallCount<0>, AllowRoCount<0>, AllowRwCount<0>>,
}

impl Otp {
    pub fn new(
        driver: &'static caliptra_mcu_romtime::Otp,
        total_heks: u32,
        grant: Grant<App, UpcallCount<0>, AllowRoCount<0>, AllowRwCount<0>>,
    ) -> Otp {
        Otp {
            driver,
            total_heks,
            apps: grant,
        }
    }

    fn read_reg(&self, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| match app.reg_offset {
            // TODO: investigate using a cache instead of the actual fuses to reduce wear and
            // increase performance
            reg::LOCK_TOTAL_HEKS => CommandReturn::success_u32(self.total_heks),
            _hek @ reg::LOCK_HEK_PROD_0
            | _hek @ reg::LOCK_HEK_PROD_1
            | _hek @ reg::LOCK_HEK_PROD_2
            | _hek @ reg::LOCK_HEK_PROD_3
            | _hek @ reg::LOCK_HEK_PROD_4
            | _hek @ reg::LOCK_HEK_PROD_5
            | _hek @ reg::LOCK_HEK_PROD_6
            | _hek @ reg::LOCK_HEK_PROD_7 => CommandReturn::failure(ErrorCode::NOSUPPORT),
            reg::CALIPTRA_FW_SVN => {
                let svn_fuses = OTP_CPTRA_CORE_RUNTIME_SVN;
                let svn_num_words = svn_fuses.byte_size / 4;
                if app.reg_index >= svn_num_words as u32 {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }

                // Read the SVN from fuses
                let svn = match self.driver.read_cptra_core_runtime_svn() {
                    Ok(svn) => svn,
                    Err(_) => return CommandReturn::failure(ErrorCode::FAIL),
                };
                let offset = app.reg_index as usize * 4;
                CommandReturn::success_u32(u32::from_le_bytes(
                    svn[offset..offset + 4].try_into().unwrap(),
                ))
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }) {
            Ok(ret) => ret,
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        }
    }

    fn write_reg(&self, value: u32, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| match app.reg_offset {
            _hek @ reg::LOCK_HEK_PROD_0
            | _hek @ reg::LOCK_HEK_PROD_1
            | _hek @ reg::LOCK_HEK_PROD_2
            | _hek @ reg::LOCK_HEK_PROD_3
            | _hek @ reg::LOCK_HEK_PROD_4
            | _hek @ reg::LOCK_HEK_PROD_5
            | _hek @ reg::LOCK_HEK_PROD_6
            | _hek @ reg::LOCK_HEK_PROD_7 => CommandReturn::failure(ErrorCode::NOSUPPORT),
            reg::CALIPTRA_FW_SVN => {
                let svn_fuses = OTP_CPTRA_CORE_RUNTIME_SVN;
                let svn_num_words = svn_fuses.byte_size / 4;
                if app.reg_index >= svn_num_words as u32 {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }

                let word_addr = svn_fuses.byte_offset / 4 + app.reg_index as usize;
                match self.driver.write_word(word_addr, value) {
                    Ok(_) => CommandReturn::success(),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
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

    fn _valid_hek_slot(&self, slot: u32) -> bool {
        let slots = &reg::LOCK_HEK_PROD_ALL[..self.total_heks as usize];
        slots.contains(&slot)
    }

    fn _hek_offset(&self, slot: u32) -> Result<usize, ErrorCode> {
        if !self._valid_hek_slot(slot) {
            return Err(ErrorCode::INVAL);
        }

        match slot {
            reg::LOCK_HEK_PROD_0 => Err(ErrorCode::INVAL),
            reg::LOCK_HEK_PROD_1 => Err(ErrorCode::INVAL),
            reg::LOCK_HEK_PROD_2 => Err(ErrorCode::INVAL),
            reg::LOCK_HEK_PROD_3 => Err(ErrorCode::INVAL),
            reg::LOCK_HEK_PROD_4 => Err(ErrorCode::INVAL),
            reg::LOCK_HEK_PROD_5 => Err(ErrorCode::INVAL),
            reg::LOCK_HEK_PROD_6 => Err(ErrorCode::INVAL),
            reg::LOCK_HEK_PROD_7 => Err(ErrorCode::INVAL),
            _ => Err(ErrorCode::INVAL),
        }
    }
}

/// Provide an interface for userland.
impl SyscallDriver for Otp {
    fn command(&self, cmd: usize, arg1: usize, arg2: usize, processid: ProcessId) -> CommandReturn {
        match cmd as u32 {
            cmd::OTP_READ => self.read_reg(processid),
            cmd::OTP_WRITE => self.write_reg(arg1 as u32, processid),
            cmd::OTP_SET_REGISTER => self.set_reg(arg1 as u32, arg2 as u32, processid),
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
