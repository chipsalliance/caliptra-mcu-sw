// Licensed under the Apache-2.0 license

//! # MCI: An Interface for accessing the Manufacturer Controller Interface (MCI)

use crate::DefaultSyscalls;
use core::marker::PhantomData;
use libtock_platform::{ErrorCode, Syscalls};

pub struct Mci<S: Syscalls = DefaultSyscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Default for Mci<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> Mci<S> {
    pub fn new() -> Self {
        Self {
            syscall: PhantomData,
            driver_num: MCI_DRIVER_NUM,
        }
    }

    pub fn read(&self, reg_offset: u32, index: u32) -> Result<u32, ErrorCode> {
        S::command(self.driver_num, cmd::MCI_SET_REGISTER, reg_offset, index)
            .to_result::<(), ErrorCode>()?;

        S::command(self.driver_num, cmd::MCI_READ, reg_offset, index).to_result::<u32, ErrorCode>()
    }

    pub fn write(&self, reg_offset: u32, index: u32, value: u32) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::MCI_SET_REGISTER, reg_offset, index)
            .to_result::<(), ErrorCode>()?;

        S::command(self.driver_num, cmd::MCI_WRITE, value, 0).to_result::<(), ErrorCode>()
    }

    pub fn trigger_warm_reset(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::MCI_TRIGGER_WARM_RESET, 0, 0).to_result::<(), ErrorCode>()
    }
}

// -----------------------------------------------------------------------------
// Command IDs and MCI-specific constants
// -----------------------------------------------------------------------------

// Driver number for the MCI interface
pub const MCI_DRIVER_NUM: u32 = 0xB000_0000;

pub mod cmd {
    pub const MCI_READ: u32 = 1;
    pub const MCI_WRITE: u32 = 2;
    pub const MCI_SET_REGISTER: u32 = 3;
    pub const MCI_TRIGGER_WARM_RESET: u32 = 4;
}

pub mod mci_reg {
    pub const RESET_REASON: u32 = 0x38;
    pub const WDT_TIMER1_EN: u32 = 0xb0;
    pub const NOTIF0_INTR_TRIG_R: u32 = 0x1034;
}
