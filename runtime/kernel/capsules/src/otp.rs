// Licensed under the Apache-2.0 license

//! This provides the OTP capsule that calls the underlying OTP driver

use caliptra_mcu_error::McuError;
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_otp_digest::{caliptra_mcu_otp_digest, OTP_DIGEST_CONST, OTP_DIGEST_IV};
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_registers_generated::fuses;
use caliptra_mcu_registers_generated::fuses::{
    OTP_CPTRA_CORE_RUNTIME_SVN, OTP_CPTRA_CORE_VENDOR_PK_HASH_0,
    OTP_CPTRA_CORE_VENDOR_PK_HASH_VALID,
};
use caliptra_mcu_romtime::println;
#[cfg(feature = "ocp-lock")]
use core::cell::Cell;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
#[cfg(feature = "ocp-lock")]
use kernel::processbuffer::ReadableProcessBuffer;
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

#[cfg(feature = "ocp-lock")]
use caliptra_mcu_romtime::ocp_lock::PlatformRuntime;
use caliptra_mcu_romtime::{fuse_lock_partition_dai, fuse_write_dai};

#[cfg(feature = "ocp-lock")]
mod ro_allow {
    pub const SEED: usize = 0;
    pub const COUNT: u8 = 1;
}
#[cfg(not(feature = "ocp-lock"))]
mod ro_allow {
    pub const COUNT: u8 = 0;
}

/// The driver number for Caliptra OTP commands.
pub const DRIVER_NUM: usize = 0xD000_0000;

pub mod cmd {
    pub const OTP_READ: u32 = 1;
    pub const OTP_WRITE: u32 = 2;
    pub const OTP_SET_REGISTER: u32 = 3;
    pub const OTP_READ_RAW: u32 = 4;
    pub const OTP_WRITE_RAW: u32 = 5;
    pub const OTP_LOCK_PARTITION: u32 = 6;
    pub const OTP_GET_HEK_METADATA: u32 = 8; // Returns (total_slots, active_slot)
    pub const OTP_ROTATE_HEK: u32 = 9;
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

    pub const VENDOR_ECC_REVOCATION: u32 = 27;
    pub const VENDOR_LMS_REVOCATION: u32 = 28;
    pub const VENDOR_MLDSA_REVOCATION: u32 = 29;
    pub const PERMA_HEK_EN: u32 = 33;
}

#[derive(Default)]
pub struct App {
    pub reg_offset: u32,
    pub reg_index: u32,
}

#[cfg(feature = "ocp-lock")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OcpLockState {
    pub total_slots: u32,
    pub active_slot: u32,
}

#[cfg(feature = "ocp-lock")]
pub struct OcpLockContext {
    pub state: OcpLockState,
    pub platform: &'static dyn PlatformRuntime,
    pub has_rotated: Cell<bool>,
}

#[cfg(feature = "ocp-lock")]
impl OcpLockContext {
    pub fn new(state: OcpLockState, platform: &'static dyn PlatformRuntime) -> Self {
        Self {
            state,
            platform,
            has_rotated: Cell::new(false),
        }
    }
}

pub struct Otp {
    driver: &'static caliptra_mcu_romtime::Otp,
    #[cfg(feature = "ocp-lock")]
    ocp_lock_ctx: Option<OcpLockContext>,

    // Per-app state.
    apps: Grant<App, UpcallCount<0>, AllowRoCount<{ ro_allow::COUNT }>, AllowRwCount<0>>,
}

impl Otp {
    pub fn new(
        driver: &'static caliptra_mcu_romtime::Otp,
        #[cfg(feature = "ocp-lock")] ocp_lock_ctx: Option<OcpLockContext>,
        grant: Grant<App, UpcallCount<0>, AllowRoCount<{ ro_allow::COUNT }>, AllowRwCount<0>>,
    ) -> Otp {
        Otp {
            driver,
            #[cfg(feature = "ocp-lock")]
            ocp_lock_ctx,

            apps: grant,
        }
    }

    fn read_reg(&self, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| match app.reg_offset {
            // TODO: investigate using a cache instead of the actual fuses to reduce wear and
            // increase performance
            #[cfg(feature = "ocp-lock")]
            reg::LOCK_TOTAL_HEKS => {
                if let Some(ctrl) = self.ocp_lock_ctx.as_ref() {
                    CommandReturn::success_u32(ctrl.state.total_slots)
                } else {
                    CommandReturn::failure(ErrorCode::NOSUPPORT)
                }
            }
            #[cfg(feature = "ocp-lock")]
            hek if self.is_hek_slot(hek) => {
                let ocp = match self.ocp_lock_ctx.as_ref() {
                    Some(ctrl) => ctrl.state,
                    None => return CommandReturn::failure(ErrorCode::NOSUPPORT),
                };
                // TODO: investigate using a cache instead of the actual fuses to reduce wear and
                // increase performance
                let hek_num_words = fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_SIZE / 4;
                if app.reg_index >= hek_num_words as u32 {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }
                let offset = match self.hek_offset(ocp, hek) {
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
            reg::VENDOR_ECC_REVOCATION => {
                match self
                    .driver
                    .read_vendor_ecc_revocation(app.reg_index as usize)
                {
                    Ok(val) => CommandReturn::success_u32(val),
                    Err(_) => CommandReturn::failure(ErrorCode::INVAL),
                }
            }
            reg::VENDOR_LMS_REVOCATION => {
                match self
                    .driver
                    .read_vendor_lms_revocation(app.reg_index as usize)
                {
                    Ok(val) => CommandReturn::success_u32(val),
                    Err(_) => CommandReturn::failure(ErrorCode::INVAL),
                }
            }
            reg::VENDOR_MLDSA_REVOCATION => {
                match self
                    .driver
                    .read_vendor_mldsa_revocation(app.reg_index as usize)
                {
                    Ok(val) => CommandReturn::success_u32(val),
                    Err(_) => CommandReturn::failure(ErrorCode::INVAL),
                }
            }
            #[cfg(feature = "ocp-lock")]
            reg::PERMA_HEK_EN => match self.driver.read_entry(fuses::PERMA_HEK_EN) {
                Ok(value) => CommandReturn::success_u32(value),
                Err(_) => CommandReturn::failure(ErrorCode::FAIL),
            },
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }) {
            Ok(ret) => ret,
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        }
    }

    fn write_reg(&self, value: u32, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| match app.reg_offset {
            #[cfg(feature = "ocp-lock")]
            hek if self.is_hek_slot(hek) => {
                let ocp = match self.ocp_lock_ctx.as_ref() {
                    Some(ctrl) => ctrl.state,
                    None => return CommandReturn::failure(ErrorCode::NOSUPPORT),
                };
                let hek_num_words = fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_SIZE / 4;
                if app.reg_index >= hek_num_words as u32 {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }
                let offset = match self.hek_offset(ocp, hek) {
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
                const RAW_FUSE_BYTE_SIZE: usize = OTP_CPTRA_CORE_VENDOR_PK_HASH_VALID.byte_size;
                match self.driver.write_entry_multi::<1, RAW_FUSE_BYTE_SIZE>(
                    OTP_CPTRA_CORE_VENDOR_PK_HASH_VALID,
                    &[value],
                ) {
                    Ok(_) => CommandReturn::success(),
                    Err(e) => {
                        capsule_error!("OTP", "Error Writing vendor PK hash valid mask: {:?}", e);
                        CommandReturn::failure(ErrorCode::FAIL)
                    }
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
            reg::VENDOR_ECC_REVOCATION => {
                match self
                    .driver
                    .write_vendor_ecc_revocation(app.reg_index as usize, value)
                {
                    Ok(()) => CommandReturn::success(),
                    Err(_) => CommandReturn::failure(ErrorCode::INVAL),
                }
            }
            reg::VENDOR_LMS_REVOCATION => {
                match self
                    .driver
                    .write_vendor_lms_revocation(app.reg_index as usize, value)
                {
                    Ok(()) => CommandReturn::success(),
                    Err(_) => CommandReturn::failure(ErrorCode::INVAL),
                }
            }
            reg::VENDOR_MLDSA_REVOCATION => {
                match self
                    .driver
                    .write_vendor_mldsa_revocation(app.reg_index as usize, value)
                {
                    Ok(()) => CommandReturn::success(),
                    Err(_) => CommandReturn::failure(ErrorCode::INVAL),
                }
            }
            #[cfg(feature = "ocp-lock")]
            reg::PERMA_HEK_EN => {
                // Fuses can only be programmed 0 -> 1. Only allow writing 1.
                if value != 1 {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }
                if !self.all_heks_zeroized() {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }
                match self.driver.write_entry(fuses::PERMA_HEK_EN, value) {
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

    fn read_otp_raw(&self, base_word_addr: usize, offset: usize) -> CommandReturn {
        match self.driver.read_word(base_word_addr + offset) {
            Ok(value) => CommandReturn::success_u32(value),
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        }
    }

    /// Writes a word to an OTP word address.
    ///
    /// Only bits specified with `mask` are written.
    /// Bits outside of `mask` are ignored.
    ///
    /// The word offset is stored in `app.reg_offset`.
    ///
    ///
    /// # Errors
    /// - When `word_addr` is not a valid address
    /// - When any of the existing data is `1` but is set to `0` in the input data
    fn write_otp_raw(&self, data: u32, mask: u32, processid: ProcessId) -> CommandReturn {
        match self.apps.enter(processid, |app, _| {
            let word_addr = app.reg_offset;

            // TODO check that word_addr is valid to return `ErrorCode::INVAL` in that case

            match fuse_write_dai(self.driver, word_addr, data, mask) {
                Ok(_) => CommandReturn::success(),
                Err(McuError::ROM_OTP_FUSE_DAI_WRITE_ERROR) => {
                    CommandReturn::failure(ErrorCode::INVAL)
                }
                Err(_) => CommandReturn::failure(ErrorCode::FAIL),
            }
        }) {
            Ok(c) => c,
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        }
    }
    fn lock_otp_partition(&self, partition: u32) -> CommandReturn {
        match fuse_lock_partition_dai(self.driver, partition) {
            Ok(_) => CommandReturn::success(),
            Err(McuError::ROM_OTP_FUSE_INVALID_PARTITION) => {
                CommandReturn::failure(ErrorCode::INVAL)
            }
            Err(_) => CommandReturn::failure(ErrorCode::FAIL),
        }
    }
}

#[cfg(feature = "ocp-lock")]
impl Otp {
    fn get_hek_metadata(&self) -> CommandReturn {
        match self.ocp_lock_ctx.as_ref() {
            Some(ctrl) => {
                CommandReturn::success_u32_u32(ctrl.state.total_slots, ctrl.state.active_slot)
            }
            None => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    #[cfg(feature = "ocp-lock")]
    fn is_hek_slot(&self, slot: u32) -> bool {
        match self.ocp_lock_ctx.as_ref() {
            Some(ctrl) => self.valid_hek_slot(ctrl.state, slot),
            None => false,
        }
    }

    #[cfg(feature = "ocp-lock")]
    fn valid_hek_slot(&self, ocp: OcpLockState, slot: u32) -> bool {
        slot >= 1 && slot <= ocp.total_slots
    }

    #[cfg(feature = "ocp-lock")]
    fn hek_offset(&self, ocp: OcpLockState, slot: u32) -> Result<usize, ErrorCode> {
        if !self.valid_hek_slot(ocp, slot) {
            return Err(ErrorCode::INVAL);
        }
        let ocp_lock_ctx = self.ocp_lock_ctx.as_ref().ok_or(ErrorCode::NOSUPPORT)?;
        let slot_index = (slot - 1) as usize;
        ocp_lock_ctx
            .platform
            .get_hek_slot_offset(slot_index)
            .map_err(|_| ErrorCode::FAIL)
    }

    #[cfg(feature = "ocp-lock")]
    fn all_heks_zeroized(&self) -> bool {
        let ocp_lock_ctx = match self.ocp_lock_ctx.as_ref() {
            Some(ctrl) => ctrl,
            None => return false,
        };
        (0..ocp_lock_ctx.state.total_slots as usize).all(|idx| {
            if let Ok(true) = ocp_lock_ctx.platform.is_hek_slot_zeroized(self.driver, idx) {
                true
            } else {
                false
            }
        })
    }
}

/// Provide an interface for userland.
impl SyscallDriver for Otp {
    fn command(&self, cmd: usize, arg1: usize, arg2: usize, processid: ProcessId) -> CommandReturn {
        match cmd as u32 {
            cmd::OTP_READ => self.read_reg(processid),
            cmd::OTP_WRITE => self.write_reg(arg1 as u32, processid),
            cmd::OTP_SET_REGISTER => self.set_reg(arg1 as u32, arg2 as u32, processid),
            cmd::OTP_READ_RAW => self.read_otp_raw(arg1, arg2),
            cmd::OTP_WRITE_RAW => self.write_otp_raw(arg1 as u32, arg2 as u32, processid),
            cmd::OTP_LOCK_PARTITION => self.lock_otp_partition(arg1 as u32),
            #[cfg(feature = "ocp-lock")]
            cmd::OTP_GET_HEK_METADATA => self.get_hek_metadata(),
            #[cfg(feature = "ocp-lock")]
            cmd::OTP_ROTATE_HEK => self.rotate_hek(arg1, processid),
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}

#[cfg(feature = "ocp-lock")]
impl Otp {
    fn is_perma_hek_locked(&self) -> Result<bool, ErrorCode> {
        let ocp_lock_ctx = self.ocp_lock_ctx.as_ref().ok_or(ErrorCode::NOSUPPORT)?;
        ocp_lock_ctx
            .platform
            .is_perma_bit_set(self.driver)
            .map_err(|_| ErrorCode::FAIL)
    }

    fn rotate_hek(&self, slot: usize, processid: ProcessId) -> CommandReturn {
        let ocp_lock_ctx = match self.ocp_lock_ctx.as_ref() {
            Some(ctrl) => ctrl,
            None => return CommandReturn::failure(ErrorCode::NOSUPPORT),
        };

        let active_slot = ocp_lock_ctx.state.active_slot;
        let total_slots = ocp_lock_ctx.state.total_slots;

        if slot >= total_slots as usize {
            return CommandReturn::failure(ErrorCode::INVAL);
        }

        if ocp_lock_ctx.has_rotated.get() {
            return CommandReturn::failure(ErrorCode::ALREADY);
        }

        // NOP: Perma bit set.
        if let Ok(true) = self.is_perma_hek_locked() {
            return CommandReturn::success();
        }

        if active_slot >= total_slots {
            return CommandReturn::failure(ErrorCode::INVAL);
        }

        let res = self.apps.enter(processid, |_, kernel_data| {
            let seed_buf = kernel_data
                .get_readonly_processbuffer(ro_allow::SEED)
                .map_err(|_| ErrorCode::INVAL)?;

            let mut seed = [0u8; 32];
            let res = seed_buf.enter(|buf| {
                if buf.len() != 32 {
                    return Err(ErrorCode::INVAL);
                }
                buf.copy_to_slice(&mut seed);
                Ok(())
            });

            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(ErrorCode::FAIL),
            }

            ocp_lock_ctx
                .platform
                .validate_hek_transition(active_slot as usize, slot, total_slots as usize)
                .map_err(|_| ErrorCode::INVAL)?;

            let digest = caliptra_mcu_otp_digest(&seed, OTP_DIGEST_IV, OTP_DIGEST_CONST);
            ocp_lock_ctx
                .platform
                .sanitize_hek_slot(self.driver, active_slot as usize)
                .map_err(|_| ErrorCode::FAIL)?;
            ocp_lock_ctx.has_rotated.set(true);

            ocp_lock_ctx
                .platform
                .program_hek_slot(self.driver, slot, &seed, digest)
                .map_err(|_| ErrorCode::FAIL)?;

            Ok(())
        });

        match res {
            Ok(Ok(())) => CommandReturn::success(),
            Ok(Err(e)) => CommandReturn::failure(e),
            Err(e) => CommandReturn::failure(e.into()),
        }
    }
}
