// Licensed under the Apache-2.0 license

use crate::{error::McuError, static_ref::StaticRef};
use core::fmt::Write;
use registers_generated::fuses;
use registers_generated::fuses::Fuses;
use registers_generated::otp_ctrl;
use tock_registers::interfaces::{Readable, Writeable};

// TODO: use the Lifecycle controller to read the Lifecycle state

pub struct Otp {
    registers: StaticRef<otp_ctrl::regs::OtpCtrl>,
}

impl Otp {
    pub const fn new(registers: StaticRef<otp_ctrl::regs::OtpCtrl>) -> Self {
        Otp { registers }
    }

    pub fn init(&self) -> Result<(), McuError> {
        if self.registers.status.get() & 0x1fff != 0 {
            romtime::println!("OTP error: {:x}", self.registers.status.get());
            return Err(McuError::FusesError);
        }

        // OTP DAI status should be idle
        if !self
            .registers
            .status
            .is_set(otp_ctrl::bits::Status::DailIdle)
        {
            romtime::println!("OTP not idle");
            return Err(McuError::FusesError);
        }

        // Disable periodic background checks
        self.registers.consistency_check_period.set(0);
        self.registers.integrity_check_period.set(0);
        self.registers.check_timeout.set(0);
        // Disable modifications to the background checks
        self.registers
            .check_regwen
            .write(otp_ctrl::bits::CheckRegwen::Regwen::CLEAR);
        Ok(())
    }

    fn read_data(
        &self,
        word_addr: usize,
        word_len: usize,
        data: &mut [u32],
    ) -> Result<(), McuError> {
        if data.len() < word_len {
            return Err(McuError::InvalidDataError);
        }
        for i in 0..word_len {
            data[i] = self.read_word(word_addr + i)?;
        }
        Ok(())
    }

    fn read_word(&self, word_addr: usize) -> Result<u32, McuError> {
        // OTP DAI status should be idle
        while !self
            .registers
            .status
            .is_set(otp_ctrl::bits::Status::DailIdle)
        {}

        self.registers
            .direct_access_address
            .set((word_addr * 4) as u32);
        // trigger a read
        self.registers.direct_access_cmd.set(1);

        // wait for DAI to go back to idle
        while !self
            .registers
            .status
            .is_set(otp_ctrl::bits::Status::DailIdle)
        {}

        if let Some(err) = self.check_error() {
            romtime::println!("Error reading fuses: {:x}", err);
            return Err(McuError::FusesError);
        }
        Ok(self.registers.dai_rdata_rf_direct_access_rdata_0.get())
    }

    pub fn check_error(&self) -> Option<u32> {
        let status = self.registers.status.get() & 0x1fff;
        if status == 0 {
            None
        } else {
            Some(status)
        }
    }

    pub fn read_fuses(&self) -> Result<Fuses, McuError> {
        let mut fuses = Fuses::default();
        self.read_data(
            fuses::NON_SECRET_FUSES_WORD_OFFSET,
            fuses::NON_SECRET_FUSES_WORD_SIZE,
            &mut fuses.non_secret_fuses,
        )?;
        Ok(fuses)
    }
}
