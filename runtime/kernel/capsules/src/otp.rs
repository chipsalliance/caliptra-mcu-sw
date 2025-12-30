// Licensed under the Apache-2.0 license

//! This provides the OTP capsule that calls the underlying OTP driver

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};
use registers_generated::fuses::{self, Fuses};

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
}

#[derive(Default)]
pub struct App {
    pub reg_offset: u32,
    pub reg_index: u32,
}

pub struct Otp {
    driver: &'static romtime::Otp,
    total_heks: u32,
    // Per-app state.
    apps: Grant<App, UpcallCount<0>, AllowRoCount<0>, AllowRwCount<0>>,
}

impl Otp {
    pub fn new(
        driver: &'static romtime::Otp,
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
            reg::LOCK_TOTAL_HEKS => CommandReturn::success_u32(self.total_heks),
            hek @ reg::LOCK_HEK_PROD_0
            | hek @ reg::LOCK_HEK_PROD_1
            | hek @ reg::LOCK_HEK_PROD_2
            | hek @ reg::LOCK_HEK_PROD_3
            | hek @ reg::LOCK_HEK_PROD_4
            | hek @ reg::LOCK_HEK_PROD_5
            | hek @ reg::LOCK_HEK_PROD_6
            | hek @ reg::LOCK_HEK_PROD_7 => {
                // TODO: investigate using a cache instead of the actual fuses to reduce wear and
                // increase performance
                let hek_num_words = size_of_val(&Fuses::default().cptra_ss_lock_hek_prod_0) / 4;
                if app.reg_index >= hek_num_words as u32 {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }
                let offset = match self.hek_offset(hek) {
                    Ok(offset) => offset,
                    Err(e) => {
                        return CommandReturn::failure(e);
                    }
                };

                let word_offset = offset / 4 + app.reg_index as usize;
                match self.driver.read_word(word_offset) {
                    Ok(value) => CommandReturn::success_u32(value),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }) {
            Ok(ret) => ret,
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        }
    }

    fn write_reg(&self, value: u32, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| match app.reg_offset {
            hek @ reg::LOCK_HEK_PROD_0
            | hek @ reg::LOCK_HEK_PROD_1
            | hek @ reg::LOCK_HEK_PROD_2
            | hek @ reg::LOCK_HEK_PROD_3
            | hek @ reg::LOCK_HEK_PROD_4
            | hek @ reg::LOCK_HEK_PROD_5
            | hek @ reg::LOCK_HEK_PROD_6
            | hek @ reg::LOCK_HEK_PROD_7 => {
                let hek_num_words = size_of_val(&Fuses::default().cptra_ss_lock_hek_prod_0) / 4;
                if app.reg_index >= hek_num_words as u32 {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }
                let offset = match self.hek_offset(hek) {
                    Ok(offset) => offset,
                    Err(e) => {
                        return CommandReturn::failure(e);
                    }
                };

                let word_offset = offset / 4 + app.reg_index as usize;
                match self.driver.write_word(word_offset, value) {
                    Ok(written) if written == value => CommandReturn::success(),
                    Ok(_) => CommandReturn::failure(ErrorCode::FAIL),
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

    fn valid_hek_slot(&self, slot: u32) -> bool {
        let slots = &reg::LOCK_HEK_PROD_ALL[..self.total_heks as usize];
        slots.contains(&slot)
    }

    fn hek_offset(&self, slot: u32) -> Result<usize, ErrorCode> {
        if !self.valid_hek_slot(slot) {
            return Err(ErrorCode::INVAL);
        }

        match slot {
            reg::LOCK_HEK_PROD_0 => Ok(fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_OFFSET),
            reg::LOCK_HEK_PROD_1 => Ok(fuses::CPTRA_SS_LOCK_HEK_PROD_1_BYTE_OFFSET),
            reg::LOCK_HEK_PROD_2 => Ok(fuses::CPTRA_SS_LOCK_HEK_PROD_2_BYTE_OFFSET),
            reg::LOCK_HEK_PROD_3 => Ok(fuses::CPTRA_SS_LOCK_HEK_PROD_3_BYTE_OFFSET),
            reg::LOCK_HEK_PROD_4 => Ok(fuses::CPTRA_SS_LOCK_HEK_PROD_4_BYTE_OFFSET),
            reg::LOCK_HEK_PROD_5 => Ok(fuses::CPTRA_SS_LOCK_HEK_PROD_5_BYTE_OFFSET),
            reg::LOCK_HEK_PROD_6 => Ok(fuses::CPTRA_SS_LOCK_HEK_PROD_6_BYTE_OFFSET),
            reg::LOCK_HEK_PROD_7 => Ok(fuses::CPTRA_SS_LOCK_HEK_PROD_7_BYTE_OFFSET),
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
