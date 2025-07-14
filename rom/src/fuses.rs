// Licensed under the Apache-2.0 license

use core::fmt::Write;
use registers_generated::fuses;
use registers_generated::fuses::Fuses;
use registers_generated::otp_ctrl;
use romtime::{HexWord, McuError, StaticRef};
use tock_registers::interfaces::{Readable, Writeable};

// TODO: use the Lifecycle controller to read the Lifecycle state

const OTP_STATUS_ERROR_MASK: u32 = (1 << 22) - 1;
const OTP_CONSISTENCY_CHECK_PERIOD_MASK: u32 = 0x3ff_ffff;
const OTP_INTEGRITY_CHECK_PERIOD_MASK: u32 = 0x3ff_ffff;
const OTP_CHECK_TIMEOUT: u32 = 0x10_0000;

pub struct Otp {
    registers: StaticRef<otp_ctrl::regs::OtpCtrl>,
}

impl Otp {
    pub const fn new(registers: StaticRef<otp_ctrl::regs::OtpCtrl>) -> Self {
        Otp { registers }
    }

    pub fn init(&self) -> Result<(), McuError> {
        romtime::println!("Initializing OTP controller...");
        if self.registers.otp_status.get() & OTP_STATUS_ERROR_MASK != 0 {
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

        // Enable periodic background checks
        romtime::println!("Enabling consistency check period");
        self.registers
            .consistency_check_period
            .set(OTP_CONSISTENCY_CHECK_PERIOD_MASK);
        romtime::println!("Enabling integrity check period");
        self.registers
            .integrity_check_period
            .set(OTP_INTEGRITY_CHECK_PERIOD_MASK);
        romtime::println!("Enabling check timeout");
        self.registers.check_timeout.set(OTP_CHECK_TIMEOUT);
        // Disable modifications to the background checks
        romtime::println!("Disabling check modifications");
        self.registers
            .check_regwen
            .write(otp_ctrl::bits::CheckRegwen::Regwen::CLEAR);
        romtime::println!("Done init");
        Ok(())
    }

    pub fn status(&self) -> u32 {
        self.registers.otp_status.get()
    }

    fn read_data(&self, addr: usize, len: usize, data: &mut [u8]) -> Result<(), McuError> {
        if data.len() < len || len % 4 != 0 {
            return Err(McuError::InvalidDataError);
        }
        for (i, chunk) in data[..len].chunks_exact_mut(4).enumerate() {
            let word = self.read_word(addr / 4 + i)?;
            let word_bytes = word.to_le_bytes();
            chunk.copy_from_slice(&word_bytes[..chunk.len()]);
        }
        Ok(())
    }

    /// Reads a word from the OTP controller.
    /// word_addr is in words
    pub fn read_word(&self, word_addr: usize) -> Result<u32, McuError> {
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

    /// Write a word to the OTP controller.
    /// word_addr is in words
    pub fn write_word(&self, word_addr: usize, data: u32) -> Result<u32, McuError> {
        // OTP DAI status should be idle
        while !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {}

        // load the data
        self.registers.dai_wdata_rf_direct_access_wdata_0.set(data);

        self.registers
            .direct_access_address
            .set((word_addr * 4) as u32);
        // trigger a write
        self.registers.direct_access_cmd.set(2);

        // wait for DAI to go back to idle
        while !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {}

        if let Some(err) = self.check_error() {
            romtime::println!("Error writing fuses: {}", HexWord(err));
            self.print_errors();
            return Err(McuError::FusesError);
        }
        Ok(self.registers.dai_rdata_rf_direct_access_rdata_0.get())
    }

    pub fn print_errors(&self) {
        for i in 0..18 {
            let err_code = match i {
                0 => self.registers.err_code_rf_err_code_0.get(),
                1 => self.registers.err_code_rf_err_code_1.get(),
                2 => self.registers.err_code_rf_err_code_2.get(),
                3 => self.registers.err_code_rf_err_code_3.get(),
                4 => self.registers.err_code_rf_err_code_4.get(),
                5 => self.registers.err_code_rf_err_code_5.get(),
                6 => self.registers.err_code_rf_err_code_6.get(),
                7 => self.registers.err_code_rf_err_code_7.get(),
                8 => self.registers.err_code_rf_err_code_8.get(),
                9 => self.registers.err_code_rf_err_code_9.get(),
                10 => self.registers.err_code_rf_err_code_10.get(),
                11 => self.registers.err_code_rf_err_code_11.get(),
                12 => self.registers.err_code_rf_err_code_12.get(),
                13 => self.registers.err_code_rf_err_code_13.get(),
                14 => self.registers.err_code_rf_err_code_14.get(),
                15 => self.registers.err_code_rf_err_code_15.get(),
                16 => self.registers.err_code_rf_err_code_16.get(),
                17 => self.registers.err_code_rf_err_code_17.get(),
                _ => 0,
            };
            if err_code != 0 {
                romtime::println!("OTP error code {}: {}", i, err_code);
            }
        }
    }

    pub fn check_error(&self) -> Option<u32> {
        let status = self.registers.otp_status.get() & OTP_STATUS_ERROR_MASK;
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
