// Licensed under the Apache-2.0 license

use core::fmt::Write;
use registers_generated::fuses;
use registers_generated::fuses::Fuses;
use registers_generated::otp_ctrl;
use romtime::{HexWord, McuError, StaticRef};
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
        if self.registers.otp_status.get() & ((1 << 21) - 1) != 0 {
            romtime::println!("OTP error: {}", self.registers.otp_status.get());
            return Err(McuError::FusesError);
        }

        // OTP DAI status should be idle
        if !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
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

    pub fn status(&self) -> u32 {
        self.registers.otp_status.get()
    }

    fn read_data(&self, addr: usize, len: usize, data: &mut [u8]) -> Result<(), McuError> {
        if data.len() < len || len % 4 != 0 {
            return Err(McuError::InvalidDataError);
        }
        for (i, chunk) in (&mut data[..len]).chunks_exact_mut(4).enumerate() {
            let word = self.read_word(addr / 4 + i)?;
            let word_bytes = word.to_le_bytes();
            chunk.copy_from_slice(&word_bytes[..chunk.len()]);
        }
        Ok(())
    }

    /// Reads a word from the OTP controller.
    /// word_addr is in words
    fn read_word(&self, word_addr: usize) -> Result<u32, McuError> {
        // OTP DAI status should be idle
        while !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {}

        self.registers
            .direct_access_address
            .set((word_addr * 4) as u32);
        // trigger a read
        self.registers.direct_access_cmd.set(1);

        // wait for DAI to go back to idle
        while !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {}

        if let Some(err) = self.check_error() {
            romtime::println!("Error reading fuses: {}", HexWord(err));
            return Err(McuError::FusesError);
        }
        Ok(self.registers.dai_rdata_rf_direct_access_rdata_0.get())
    }

    pub fn check_error(&self) -> Option<u32> {
        let status = self.registers.otp_status.get() & 0x1fff;
        if status == 0 {
            None
        } else {
            Some(status)
        }
    }

    pub fn read_fuses(&self) -> Result<Fuses, McuError> {
        let mut fuses = Fuses::default();
        self.read_data(
            fuses::SW_TEST_UNLOCK_PARTITION_BYTE_OFFSET,
            fuses::SW_TEST_UNLOCK_PARTITION_BYTE_SIZE,
            &mut fuses.sw_test_unlock_partition,
        )?;
        self.read_data(
            fuses::SECRET_MANUF_PARTITION_BYTE_OFFSET,
            fuses::SECRET_MANUF_PARTITION_BYTE_SIZE,
            &mut fuses.secret_manuf_partition,
        )?;
        self.read_data(
            fuses::SECRET_PROD_PARTITION_0_BYTE_OFFSET,
            fuses::SECRET_PROD_PARTITION_0_BYTE_SIZE,
            &mut fuses.secret_prod_partition_0,
        )?;
        self.read_data(
            fuses::SECRET_PROD_PARTITION_1_BYTE_OFFSET,
            fuses::SECRET_PROD_PARTITION_1_BYTE_SIZE,
            &mut fuses.secret_prod_partition_1,
        )?;
        self.read_data(
            fuses::SECRET_PROD_PARTITION_2_BYTE_OFFSET,
            fuses::SECRET_PROD_PARTITION_2_BYTE_SIZE,
            &mut fuses.secret_prod_partition_2,
        )?;
        self.read_data(
            fuses::SECRET_PROD_PARTITION_3_BYTE_OFFSET,
            fuses::SECRET_PROD_PARTITION_3_BYTE_SIZE,
            &mut fuses.secret_prod_partition_3,
        )?;
        self.read_data(
            fuses::SW_MANUF_PARTITION_BYTE_OFFSET,
            fuses::SW_MANUF_PARTITION_BYTE_SIZE,
            &mut fuses.sw_manuf_partition,
        )?;
        self.read_data(
            fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET,
            fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_SIZE,
            &mut fuses.secret_lc_transition_partition,
        )?;
        self.read_data(
            fuses::SVN_PARTITION_BYTE_OFFSET,
            fuses::SVN_PARTITION_BYTE_SIZE,
            &mut fuses.svn_partition,
        )?;
        self.read_data(
            fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_TEST_PARTITION_BYTE_SIZE,
            &mut fuses.vendor_test_partition,
        )?;
        self.read_data(
            fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_SIZE,
            &mut fuses.vendor_hashes_manuf_partition,
        )?;
        self.read_data(
            fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_SIZE,
            &mut fuses.vendor_hashes_prod_partition,
        )?;
        self.read_data(
            fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_SIZE,
            &mut fuses.vendor_revocations_prod_partition,
        )?;
        self.read_data(
            fuses::VENDOR_SECRET_PROD_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_SECRET_PROD_PARTITION_BYTE_SIZE,
            &mut fuses.vendor_secret_prod_partition,
        )?;
        self.read_data(
            fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_SIZE,
            &mut fuses.vendor_non_secret_prod_partition,
        )?;
        Ok(fuses)
    }
}
