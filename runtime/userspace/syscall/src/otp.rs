// Licensed under the Apache-2.0 license

//! # OTP: An Interface for accessing the OTP fuses

use crate::DefaultSyscalls;
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use core::marker::PhantomData;

pub const VENDOR_PK_HASH_SIZE: usize =
    caliptra_mcu_registers_generated::fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_0.byte_size;

pub struct Otp<S: Syscalls = DefaultSyscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Default for Otp<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> Otp<S> {
    pub fn new() -> Self {
        Self {
            syscall: PhantomData,
            driver_num: OTP_DRIVER_NUM,
        }
    }

    pub fn read(&self, reg_offset: u32, index: u32) -> Result<u32, ErrorCode> {
        S::command(self.driver_num, cmd::OTP_SET_REGISTER, reg_offset, index)
            .to_result::<(), ErrorCode>()?;

        S::command(self.driver_num, cmd::OTP_READ, reg_offset, index).to_result::<u32, ErrorCode>()
    }

    pub fn write(&self, reg_offset: u32, index: u32, value: u32) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::OTP_SET_REGISTER, reg_offset, index)
            .to_result::<(), ErrorCode>()?;

        S::command(self.driver_num, cmd::OTP_WRITE, value, 0).to_result::<(), ErrorCode>()
    }

    /// Check whether a given slot has a valid PK hash
    pub fn valid_vendor_pk_hash_slot(&self, slot: u32) -> bool {
        if slot >= 16 {
            return false;
        }

        let Ok(valid_mask) = self.read(reg::VENDOR_PK_HASH_VALID, 0) else {
            return false;
        };
        (valid_mask & (1 << slot)) != 0
    }

    /// Read a vendor PK hash from fuses
    pub fn read_vendor_pk_hash(&self, slot: u32) -> Result<[u8; VENDOR_PK_HASH_SIZE], ErrorCode> {
        let reg = reg::vendor_pk_hash_reg_by_slot(slot).ok_or(ErrorCode::Invalid)?;
        if !self.valid_vendor_pk_hash_slot(slot) {
            Err(ErrorCode::Invalid)?;
        }

        let mut fuse_value = [0u8; VENDOR_PK_HASH_SIZE];
        for (i, chunk) in fuse_value.chunks_exact_mut(4).enumerate() {
            let word = self.read(reg, i as u32)?;
            let bytes = word.to_le_bytes();
            chunk.copy_from_slice(&bytes);
        }

        Ok(fuse_value)
    }
}

// -----------------------------------------------------------------------------
// Command IDs and MCI-specific constants
// -----------------------------------------------------------------------------

// Driver number for the MCI interface
pub const OTP_DRIVER_NUM: u32 = 0xD000_0000;

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

    pub(super) const fn vendor_pk_hash_reg_by_slot(slot: u32) -> Option<u32> {
        match slot {
            0 => Some(VENDOR_PK_HASH_0),
            1 => Some(VENDOR_PK_HASH_1),
            2 => Some(VENDOR_PK_HASH_2),
            3 => Some(VENDOR_PK_HASH_3),
            4 => Some(VENDOR_PK_HASH_4),
            5 => Some(VENDOR_PK_HASH_5),
            6 => Some(VENDOR_PK_HASH_6),
            7 => Some(VENDOR_PK_HASH_7),
            8 => Some(VENDOR_PK_HASH_8),
            9 => Some(VENDOR_PK_HASH_9),
            10 => Some(VENDOR_PK_HASH_10),
            11 => Some(VENDOR_PK_HASH_11),
            12 => Some(VENDOR_PK_HASH_12),
            13 => Some(VENDOR_PK_HASH_13),
            14 => Some(VENDOR_PK_HASH_14),
            15 => Some(VENDOR_PK_HASH_15),
            _ => None,
        }
    }
}
