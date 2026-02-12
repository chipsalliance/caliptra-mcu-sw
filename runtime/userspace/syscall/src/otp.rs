// Licensed under the Apache-2.0 license

//! # OTP: An Interface for accessing the OTP fuses

use crate::DefaultSyscalls;
use core::marker::PhantomData;
use libtock_platform::{ErrorCode, Syscalls};

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
}
