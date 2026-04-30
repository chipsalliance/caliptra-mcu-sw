// Licensed under the Apache-2.0 license

//! This provides the OTP capsule that calls the underlying OTP driver

use caliptra_mcu_registers_generated::fuses::{
    OTP_CPTRA_CORE_RUNTIME_SVN, OTP_CPTRA_CORE_VENDOR_PK_HASH_0,
    OTP_CPTRA_CORE_VENDOR_PK_HASH_VALID,
};
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
    use caliptra_mcu_registers_generated::fuses::{
        FuseEntryInfo, OTP_CPTRA_CORE_VENDOR_PK_HASH_0, OTP_CPTRA_CORE_VENDOR_PK_HASH_1,
        OTP_CPTRA_CORE_VENDOR_PK_HASH_10, OTP_CPTRA_CORE_VENDOR_PK_HASH_11,
        OTP_CPTRA_CORE_VENDOR_PK_HASH_12, OTP_CPTRA_CORE_VENDOR_PK_HASH_13,
        OTP_CPTRA_CORE_VENDOR_PK_HASH_14, OTP_CPTRA_CORE_VENDOR_PK_HASH_15,
        OTP_CPTRA_CORE_VENDOR_PK_HASH_2, OTP_CPTRA_CORE_VENDOR_PK_HASH_3,
        OTP_CPTRA_CORE_VENDOR_PK_HASH_4, OTP_CPTRA_CORE_VENDOR_PK_HASH_5,
        OTP_CPTRA_CORE_VENDOR_PK_HASH_6, OTP_CPTRA_CORE_VENDOR_PK_HASH_7,
        OTP_CPTRA_CORE_VENDOR_PK_HASH_8, OTP_CPTRA_CORE_VENDOR_PK_HASH_9,
    };

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

    pub const VENDOR_PK_HASH_0: u32 = 10;
    pub const VENDOR_PK_HASH_1: u32 = 11;
    pub const VENDOR_PK_HASH_2: u32 = 12;
    pub const VENDOR_PK_HASH_3: u32 = 13;
    pub const VENDOR_PK_HASH_4: u32 = 14;
    pub const VENDOR_PK_HASH_5: u32 = 15;
    pub const VENDOR_PK_HASH_6: u32 = 16;
    pub const VENDOR_PK_HASH_7: u32 = 17;
    pub const VENDOR_PK_HASH_8: u32 = 18;
    pub const VENDOR_PK_HASH_9: u32 = 19;
    pub const VENDOR_PK_HASH_10: u32 = 20;
    pub const VENDOR_PK_HASH_11: u32 = 21;
    pub const VENDOR_PK_HASH_12: u32 = 22;
    pub const VENDOR_PK_HASH_13: u32 = 23;
    pub const VENDOR_PK_HASH_14: u32 = 24;
    pub const VENDOR_PK_HASH_15: u32 = 25;
    pub const VENDOR_PK_HASH_VALID: u32 = 26;

    /// Return the entry info corresponding to the VENDOR_PK_HASH_X register.
    pub(super) fn vendor_pk_hash_entry_info(reg: u32) -> Option<&'static FuseEntryInfo> {
        match reg {
            VENDOR_PK_HASH_0 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_0),
            VENDOR_PK_HASH_1 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_1),
            VENDOR_PK_HASH_2 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_2),
            VENDOR_PK_HASH_3 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_3),
            VENDOR_PK_HASH_4 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_4),
            VENDOR_PK_HASH_5 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_5),
            VENDOR_PK_HASH_6 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_6),
            VENDOR_PK_HASH_7 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_7),
            VENDOR_PK_HASH_8 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_8),
            VENDOR_PK_HASH_9 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_9),
            VENDOR_PK_HASH_10 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_10),
            VENDOR_PK_HASH_11 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_11),
            VENDOR_PK_HASH_12 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_12),
            VENDOR_PK_HASH_13 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_13),
            VENDOR_PK_HASH_14 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_14),
            VENDOR_PK_HASH_15 => Some(OTP_CPTRA_CORE_VENDOR_PK_HASH_15),
            _ => None,
        }
    }
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
            reg::VENDOR_PK_HASH_VALID => match self.driver.read_vendor_pk_hash_valid() {
                Ok(valid) => CommandReturn::success_u32(valid),
                Err(_) => CommandReturn::failure(ErrorCode::FAIL),
            },
            vendor_pk_hash @ reg::VENDOR_PK_HASH_0
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_1
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_2
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_3
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_4
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_5
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_6
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_7
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_8
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_9
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_10
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_11
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_12
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_13
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_14
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_15 => {
                let mut hash = [0u8; OTP_CPTRA_CORE_VENDOR_PK_HASH_0.byte_size];
                let Some(entry_info) = reg::vendor_pk_hash_entry_info(vendor_pk_hash) else {
                    // Internal error: vendor_pk_hash_entry_info() should match all defined VENDOR_PK_HASH_[0-X]
                    return CommandReturn::failure(ErrorCode::INVAL);
                };

                let hash_num_words = entry_info.byte_size / 4;
                if app.reg_index >= hash_num_words as u32 {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }

                match self.driver.read_entry_raw(entry_info, &mut hash) {
                    Ok(_) => {}
                    Err(_) => return CommandReturn::failure(ErrorCode::FAIL),
                }

                let offset = app.reg_index as usize * 4;
                CommandReturn::success_u32(u32::from_le_bytes(
                    hash[offset..offset + 4].try_into().unwrap(),
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
            reg::VENDOR_PK_HASH_VALID => {
                match self
                    .driver
                    .write_entry(OTP_CPTRA_CORE_VENDOR_PK_HASH_VALID, value)
                {
                    Ok(_) => CommandReturn::success(),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }
            vendor_pk_hash @ reg::VENDOR_PK_HASH_0
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_1
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_2
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_3
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_4
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_5
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_6
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_7
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_8
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_9
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_10
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_11
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_12
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_13
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_14
            | vendor_pk_hash @ reg::VENDOR_PK_HASH_15 => {
                let Some(entry_info) = reg::vendor_pk_hash_entry_info(vendor_pk_hash) else {
                    // Internal error: vendor_pk_hash_entry_info() should match all defined VENDOR_PK_HASH_[0-X]
                    return CommandReturn::failure(ErrorCode::INVAL);
                };

                let hash_num_words = entry_info.byte_size / 4;
                if app.reg_index >= hash_num_words as u32 {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }

                let word_addr = entry_info.byte_offset / 4 + app.reg_index as usize;
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
