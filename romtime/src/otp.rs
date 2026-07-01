// Licensed under the Apache-2.0 license

use crate::{HexBytes, HexWord, StaticRef};
use caliptra_mcu_error::{McuError, McuResult};
use caliptra_mcu_registers_generated::fuses::{self, FuseEntryInfo, OtpPartitionInfo};
use caliptra_mcu_registers_generated::otp_ctrl;
use tock_registers::interfaces::{Readable, Writeable};

use crate::{FuseLayout, LifecycleHashedToken, LifecycleHashedTokens, LC_TOKENS_OFFSET};

// TODO: use the Lifecycle controller to read the Lifecycle state

// TODO: this error mask is dependent on the specific fuse map
// Mask covering bits 0-29 (all error bits, excluding DaiIdle bit 30 and CheckPending bit 31).
const OTP_STATUS_ERROR_MASK: u32 = (1 << 30) - 1;
const OTP_CONSISTENCY_CHECK_PERIOD_MASK: u32 = 0x3ff_ffff;
const OTP_INTEGRITY_CHECK_PERIOD_MASK: u32 = 0x3ff_ffff;
const OTP_CHECK_TIMEOUT: u32 = 0x10_0000;
const OTP_PENDING_CHECK_MAX_ITERATIONS: u32 = 1_000_000;
pub const HEK_ZEROIZATION_VALID_BOUND: u32 = 64 - 6;

// HEK partition metadata offsets
pub const HEK_PARTITION_SIZE: usize = fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_SIZE;
pub const HEK_SEED_SIZE: usize = 32;
pub const HEK_DWORD_FIELD_SIZE: usize = 8;
pub const HEK_SW_DIGEST_OFFSET: usize = HEK_SEED_SIZE;
pub const HEK_SW_DIGEST_SIZE: usize = HEK_DWORD_FIELD_SIZE;
pub const HEK_ZER_MARKER_OFFSET: usize = HEK_SW_DIGEST_OFFSET + HEK_SW_DIGEST_SIZE;
pub const HEK_ZER_MARKER_SIZE: usize = HEK_DWORD_FIELD_SIZE;

pub const HEK_OFFSETS: [usize; 8] = [
    fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_OFFSET,
    fuses::CPTRA_SS_LOCK_HEK_PROD_1_BYTE_OFFSET,
    fuses::CPTRA_SS_LOCK_HEK_PROD_2_BYTE_OFFSET,
    fuses::CPTRA_SS_LOCK_HEK_PROD_3_BYTE_OFFSET,
    fuses::CPTRA_SS_LOCK_HEK_PROD_4_BYTE_OFFSET,
    fuses::CPTRA_SS_LOCK_HEK_PROD_5_BYTE_OFFSET,
    fuses::CPTRA_SS_LOCK_HEK_PROD_6_BYTE_OFFSET,
    fuses::CPTRA_SS_LOCK_HEK_PROD_7_BYTE_OFFSET,
];

pub const LC_TOKEN_MANUF_INDEX: usize = 7;
pub const LC_TOKEN_MANUF_TO_PROD_INDEX: usize = 8;
pub const LC_TOKEN_PROD_TO_PROD_END_INDEX: usize = 9;
pub const LC_TOKEN_RMA_INDEX: usize = 10;

pub const PROD_DEBUG_UNLOCK_PK_SIZE: usize = 48;
pub const LC_TOKEN_SIZE: usize = 16;

pub const PROD_DEBUG_UNLOCK_PK_ENTRIES: [&FuseEntryInfo; 8] = [
    fuses::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_0,
    fuses::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_1,
    fuses::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_2,
    fuses::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_3,
    fuses::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_4,
    fuses::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_5,
    fuses::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_6,
    fuses::OTP_CPTRA_SS_PROD_DEBUG_UNLOCK_PKS_7,
];

const DIGEST_SIZE: usize = 8;

#[derive(Clone, Copy)]
pub enum PqcKeyType {
    MLDSA = 1,
    LMS = 2,
}

pub struct Otp {
    registers: StaticRef<otp_ctrl::regs::OtpCtrl>,
}

impl Otp {
    pub const fn new(registers: StaticRef<otp_ctrl::regs::OtpCtrl>) -> Self {
        Otp { registers }
    }

    pub fn volatile_lock(&self, index: u32) {
        // the register is 1-indexed in hardware
        self.registers.vendor_pk_hash_volatile_lock.set(index + 1);
    }

    pub fn wait_for_not_pending(&self) -> McuResult<()> {
        for _ in 0..OTP_PENDING_CHECK_MAX_ITERATIONS {
            if !self
                .registers
                .otp_status
                .is_set(otp_ctrl::bits::OtpStatus::CheckPending)
            {
                return Ok(());
            }
        }
        Err(McuError::ROM_OTP_PENDING_TIMEOUT)
    }

    pub fn check_error_and_idle(&self) -> McuResult<()> {
        if self.registers.otp_status.get() & OTP_STATUS_ERROR_MASK != 0 {
            return Err(McuError::ROM_OTP_INIT_STATUS_ERROR);
        }

        // Wait for OTP DAI to become idle (controller may still be finishing
        // power-on initialization after subsystem reset is released).
        for _ in 0..OTP_PENDING_CHECK_MAX_ITERATIONS {
            if self
                .registers
                .otp_status
                .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
            {
                return Ok(());
            }
        }
        crate::println!("[mcu-rom-otp] OTP not idle");
        Err(McuError::ROM_OTP_INIT_NOT_IDLE)
    }

    pub fn init(
        &self,
        enable_consistency_check: bool,
        enable_integrity_check: bool,
        check_timeout_override: Option<u32>,
    ) -> McuResult<()> {
        crate::println!("[mcu-rom-otp] Initializing OTP controller...");

        self.wait_for_not_pending()?;
        self.check_error_and_idle()?;

        let check_timeout = check_timeout_override.unwrap_or(OTP_CHECK_TIMEOUT);
        crate::println!("[mcu-rom-otp] Setting check timeout to {}", check_timeout);
        self.registers.check_timeout.set(check_timeout);

        // Enable periodic background checks
        if enable_consistency_check {
            crate::println!("[mcu-rom-otp] Enabling consistency check period");
            self.registers
                .consistency_check_period
                .set(OTP_CONSISTENCY_CHECK_PERIOD_MASK);
        }
        if enable_integrity_check {
            crate::println!("[mcu-rom-otp] Enabling integrity check period");
            self.registers
                .integrity_check_period
                .set(OTP_INTEGRITY_CHECK_PERIOD_MASK);
        }

        // Disable modifications to the background checks
        crate::println!("[mcu-rom-otp] Disabling check modifications");
        self.registers
            .check_regwen
            .write(otp_ctrl::bits::CheckRegwen::Regwen::CLEAR);

        self.wait_for_not_pending()?;
        self.check_error_and_idle()?;

        crate::println!("[mcu-rom-otp] Done init");
        Ok(())
    }

    pub fn status(&self) -> u32 {
        self.registers.otp_status.get()
    }

    fn read_data(&self, addr: usize, len: usize, data: &mut [u8]) -> McuResult<()> {
        if data.len() < len || addr % 4 != 0 || len % 4 != 0 {
            return Err(McuError::ROM_OTP_INVALID_DATA_ERROR);
        }

        read_data_with(
            addr,
            len,
            data,
            |word_addr| self.read_word(word_addr),
            |dword_addr| self.read_dword(dword_addr),
        )
    }

    /// Reads a word from the OTP controller.
    /// word_addr is in words
    pub fn read_word(&self, word_addr: usize) -> McuResult<u32> {
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

        if self.check_error().is_some() {
            return Err(McuError::ROM_OTP_READ_ERROR);
        }
        Ok(self.registers.dai_rdata_rf_direct_access_rdata_0.get())
    }

    /// Reads a dword (64-bit) from the OTP controller.
    /// dword_addr is in dwords (8-byte units).
    pub fn read_dword(&self, dword_addr: usize) -> McuResult<u64> {
        while !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {}

        self.registers
            .direct_access_address
            .set((dword_addr * 8) as u32);
        self.registers.direct_access_cmd.set(1);

        while !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {}

        if self.check_error().is_some() {
            return Err(McuError::ROM_OTP_READ_ERROR);
        }
        let lo = self.registers.dai_rdata_rf_direct_access_rdata_0.get() as u64;
        let hi = self.registers.dai_rdata_rf_direct_access_rdata_1.get() as u64;
        Ok(lo | (hi << 32))
    }

    /// Write a dword to the OTP controller.
    /// word_addr is in words
    pub fn write_dword(&self, dword_addr: usize, data: u64) -> McuResult<u32> {
        // OTP DAI status should be idle
        while !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {}

        // load the data
        self.registers
            .dai_wdata_rf_direct_access_wdata_0
            .set((data) as u32);
        self.registers
            .dai_wdata_rf_direct_access_wdata_1
            .set((data >> 32) as u32);

        self.registers
            .direct_access_address
            .set((dword_addr * 8) as u32);
        // trigger a write
        self.registers.direct_access_cmd.set(2);

        // wait for DAI to go back to idle
        while !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {}

        if self.check_error().is_some() {
            return Err(McuError::ROM_OTP_WRITE_DWORD_ERROR);
        }
        Ok(self.registers.dai_rdata_rf_direct_access_rdata_0.get())
    }

    /// Write a word to the OTP controller.
    /// word_addr is in words
    pub fn write_word(&self, word_addr: usize, data: u32) -> McuResult<u32> {
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

        if self.check_error().is_some() {
            return Err(McuError::ROM_OTP_WRITE_WORD_ERROR);
        }
        Ok(self.registers.dai_rdata_rf_direct_access_rdata_0.get())
    }

    /// Finalize a partition
    /// word_addr is in words
    pub fn finalize_digest(&self, partition_base_addr: usize) -> McuResult<()> {
        crate::println!(
            "[mcu-rom] Finalizing partition at base address: {}",
            HexWord(partition_base_addr as u32)
        );
        // OTP DAI status should be idle
        while !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {}

        // Write base address of partition
        self.registers
            .direct_access_address
            .set(partition_base_addr as u32);
        // trigger a digest
        self.registers.direct_access_cmd.set(4);

        // wait for DAI to go back to idle
        while !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {}

        if self.check_error().is_some() {
            return Err(McuError::ROM_OTP_FINALIZE_DIGEST_ERROR);
        }
        Ok(())
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
                crate::println!("[mcu] OTP error code {}: {}", i, err_code);
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

    /// Makes read_data public so callers can read arbitrary OTP regions.
    pub fn read_otp_data(&self, byte_offset: usize, data: &mut [u8]) -> McuResult<()> {
        self.read_data(byte_offset, data.len(), data)
    }

    /// Reads a u32 from OTP at the given byte offset.
    pub fn read_u32_at(&self, byte_offset: usize) -> McuResult<u32> {
        let mut data = [0u8; 4];
        self.read_data(byte_offset, data.len(), &mut data)?;
        Ok(u32::from_le_bytes(data))
    }

    /// Reads multiple u32 words from OTP starting at byte_offset directly into a register array.
    pub fn read_words_to_registers<F>(
        &self,
        byte_offset: usize,
        count: usize,
        mut write_fn: F,
    ) -> McuResult<()>
    where
        F: FnMut(usize, u32),
    {
        for i in 0..count {
            let word = self.read_u32_at(byte_offset + i * 4)?;
            write_fn(i, word);
        }
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Partition reading methods - read specific partitions from OTP directly
    // -------------------------------------------------------------------------

    /// Read the SVN partition (40 bytes).
    pub fn read_svn_partition(
        &self,
        data: &mut [u8; fuses::SVN_PARTITION_BYTE_SIZE],
    ) -> McuResult<()> {
        self.read_data(
            fuses::SVN_PARTITION_BYTE_OFFSET,
            fuses::SVN_PARTITION_BYTE_SIZE,
            data,
        )
    }

    /// Read the vendor test partition (64 bytes).
    pub fn read_vendor_test_partition(
        &self,
        data: &mut [u8; fuses::VENDOR_TEST_PARTITION_BYTE_SIZE],
    ) -> McuResult<()> {
        self.read_data(
            fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_TEST_PARTITION_BYTE_SIZE,
            data,
        )
    }

    /// Read a single word from the vendor test partition.
    /// word_idx is the word index (0-15 for 64 bytes).
    pub fn read_vendor_test_word(&self, word_idx: usize) -> McuResult<u32> {
        self.read_u32_at(fuses::VENDOR_TEST_PARTITION_BYTE_OFFSET + word_idx * 4)
    }

    /// Read the vendor hashes manufacturing partition (64 bytes).
    pub fn read_vendor_hashes_manuf_partition(
        &self,
        data: &mut [u8; fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_SIZE],
    ) -> McuResult<()> {
        self.read_data(
            fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_SIZE,
            data,
        )
    }

    /// Read the vendor hashes production partition (864 bytes).
    pub fn read_vendor_hashes_prod_partition(
        &self,
        data: &mut [u8; fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_SIZE],
    ) -> McuResult<()> {
        self.read_data(
            fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_SIZE,
            data,
        )
    }

    /// Read the vendor revocations production partition (216 bytes).
    pub fn read_vendor_revocations_prod_partition(
        &self,
        data: &mut [u8; fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_SIZE],
    ) -> McuResult<()> {
        self.read_data(
            fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_SIZE,
            data,
        )
    }

    /// Read the SW test unlock partition (72 bytes).
    pub fn read_sw_test_unlock_partition(
        &self,
        data: &mut [u8; fuses::SW_TEST_UNLOCK_PARTITION_BYTE_SIZE],
    ) -> McuResult<()> {
        self.read_data(
            fuses::SW_TEST_UNLOCK_PARTITION_BYTE_OFFSET,
            fuses::SW_TEST_UNLOCK_PARTITION_BYTE_SIZE,
            data,
        )
    }

    /// Read the SW manufacturing partition (520 bytes).
    pub fn read_sw_manuf_partition(
        &self,
        data: &mut [u8; fuses::SW_MANUF_PARTITION_BYTE_SIZE],
    ) -> McuResult<()> {
        self.read_data(
            fuses::SW_MANUF_PARTITION_BYTE_OFFSET,
            fuses::SW_MANUF_PARTITION_BYTE_SIZE,
            data,
        )
    }

    // -------------------------------------------------------------------------
    // Individual fuse value reading methods - read specific fuse fields directly
    // These avoid allocating full partition arrays on the stack.
    // -------------------------------------------------------------------------

    /// Read PQC key type (4 bytes).
    pub fn read_pqc_key_type(&self, index: usize) -> McuResult<PqcKeyType> {
        let entry = pqc_key_type_entry(index)?;
        if self.read_entry(entry)? == 1 {
            Ok(PqcKeyType::MLDSA)
        } else {
            Ok(PqcKeyType::LMS)
        }
    }

    /// Read cptra_core_fmc_key_manifest_svn (4 bytes).
    pub fn read_cptra_core_fmc_key_manifest_svn(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_entry_raw(fuses::OTP_CPTRA_CORE_FMC_KEY_MANIFEST_SVN, &mut data)?;
        Ok(data)
    }

    /// Read vendor public key hash (48 bytes).
    pub fn read_vendor_pk_hash(&self, index: usize, buf: &mut [u8]) -> McuResult<()> {
        let entry = vendor_pk_hash_entry(index)?;
        self.read_entry_raw(entry, buf)
    }

    /// Read vendor public key hash valid.
    pub fn read_vendor_pk_hash_valid(&self) -> McuResult<u32> {
        let val = self.read_entry_multi::<1>(fuses::VENDOR_PK_HASH_VALID)?;
        Ok(val[0])
    }

    /// Read cptra_core_runtime_svn (16 bytes).
    pub fn read_cptra_core_runtime_svn(
        &self,
    ) -> McuResult<[u8; fuses::OTP_CPTRA_CORE_RUNTIME_SVN.byte_size]> {
        let mut data = [0u8; fuses::OTP_CPTRA_CORE_RUNTIME_SVN.byte_size];
        self.read_entry_raw(fuses::OTP_CPTRA_CORE_RUNTIME_SVN, &mut data)?;
        Ok(data)
    }

    /// Read cptra_core_soc_manifest_svn (16 bytes).
    pub fn read_cptra_core_soc_manifest_svn(
        &self,
    ) -> McuResult<[u8; fuses::OTP_CPTRA_CORE_SOC_MANIFEST_SVN.byte_size]> {
        let mut data = [0u8; fuses::OTP_CPTRA_CORE_SOC_MANIFEST_SVN.byte_size];
        self.read_entry_raw(fuses::OTP_CPTRA_CORE_SOC_MANIFEST_SVN, &mut data)?;
        Ok(data)
    }

    /// Read cptra_core_soc_manifest_max_svn (4 bytes).
    pub fn read_cptra_core_soc_manifest_max_svn(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_entry_raw(fuses::OTP_CPTRA_CORE_SOC_MANIFEST_MAX_SVN, &mut data)?;
        Ok(data)
    }

    /// Read cptra_ss_manuf_debug_unlock_token (64 bytes).
    pub fn read_cptra_ss_manuf_debug_unlock_token(
        &self,
    ) -> McuResult<[u8; fuses::OTP_CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN.byte_size]> {
        let mut data = [0u8; fuses::OTP_CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN.byte_size];
        self.read_entry_raw(fuses::OTP_CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN, &mut data)?;
        Ok(data)
    }

    /// Read vendor ECC revocation (4 bytes).
    pub fn read_vendor_ecc_revocation(&self, index: usize) -> McuResult<u32> {
        let entry = vendor_ecc_revocation_entry(index)?;
        self.read_entry(entry)
    }

    /// Read vendor LMS revocation (4 bytes).
    pub fn read_vendor_lms_revocation(&self, index: usize) -> McuResult<u32> {
        let entry = vendor_lms_revocation_entry(index)?;
        self.read_entry(entry)
    }

    /// Read vendor MLDSA revocation (4 bytes).
    pub fn read_vendor_mldsa_revocation(&self, index: usize) -> McuResult<u32> {
        let entry = vendor_mldsa_revocation_entry(index)?;
        self.read_entry(entry)
    }

    /// Write vendor ECC revocation (4 bytes).
    pub fn write_vendor_ecc_revocation(&self, index: usize, value: u32) -> McuResult<()> {
        let entry = vendor_ecc_revocation_entry(index)?;
        self.write_entry(entry, value)
    }

    /// Write vendor LMS revocation (4 bytes).
    pub fn write_vendor_lms_revocation(&self, index: usize, value: u32) -> McuResult<()> {
        let entry = vendor_lms_revocation_entry(index)?;
        self.write_entry(entry, value)
    }

    /// Write vendor MLDSA revocation (4 bytes).
    pub fn write_vendor_mldsa_revocation(&self, index: usize, value: u32) -> McuResult<()> {
        let entry = vendor_mldsa_revocation_entry(index)?;
        self.write_entry(entry, value)
    }

    /// Read cptra_ss_owner_pk_hash (48 bytes).
    pub fn read_cptra_ss_owner_pk_hash(
        &self,
    ) -> McuResult<[u8; fuses::OTP_CPTRA_SS_OWNER_PK_HASH.byte_size]> {
        let mut data = [0u8; fuses::OTP_CPTRA_SS_OWNER_PK_HASH.byte_size];
        self.read_entry_raw(fuses::OTP_CPTRA_SS_OWNER_PK_HASH, &mut data)?;
        Ok(data)
    }

    /// Read cptra_core_soc_stepping_id (4 bytes).
    pub fn read_cptra_core_soc_stepping_id(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_entry_raw(fuses::OTP_CPTRA_CORE_SOC_STEPPING_ID, &mut data)?;
        Ok(data)
    }

    /// Read cptra_core_anti_rollback_disable (4 bytes).
    pub fn read_cptra_core_anti_rollback_disable(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_entry_raw(fuses::OTP_CPTRA_CORE_ANTI_ROLLBACK_DISABLE, &mut data)?;
        Ok(data)
    }

    /// Read cptra_core_idevid_cert_idevid_attr (96 bytes).
    pub fn read_cptra_core_idevid_cert_idevid_attr(
        &self,
    ) -> McuResult<[u8; fuses::OTP_CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR.byte_size]> {
        let mut data = [0u8; fuses::OTP_CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR.byte_size];
        self.read_entry_raw(fuses::OTP_CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR, &mut data)?;
        Ok(data)
    }

    /// Read cptra_core_idevid_manuf_hsm_identifier (16 bytes).
    pub fn read_cptra_core_idevid_manuf_hsm_identifier(
        &self,
    ) -> McuResult<[u8; fuses::OTP_CPTRA_CORE_IDEVID_MANUF_HSM_IDENTIFIER.byte_size]> {
        let mut data = [0u8; fuses::OTP_CPTRA_CORE_IDEVID_MANUF_HSM_IDENTIFIER.byte_size];
        self.read_entry_raw(fuses::OTP_CPTRA_CORE_IDEVID_MANUF_HSM_IDENTIFIER, &mut data)?;
        Ok(data)
    }

    /// Read cptra_ss_prod_debug_unlock_pks (index 0-7, each 48 bytes).
    pub fn read_cptra_ss_prod_debug_unlock_pks(
        &self,
        index: usize,
    ) -> McuResult<[u8; PROD_DEBUG_UNLOCK_PK_SIZE]> {
        let entry = PROD_DEBUG_UNLOCK_PK_ENTRIES
            .get(index)
            .ok_or(McuError::ROM_OTP_INVALID_DATA_ERROR)?;
        let mut data = [0u8; PROD_DEBUG_UNLOCK_PK_SIZE];
        self.read_entry_raw(entry, &mut data)?;
        Ok(data)
    }

    /// Read from vendor non-secret prod partition
    pub fn read_vendor_non_secret_prod_partition(&self, data: &mut [u8]) -> McuResult<()> {
        let len = data
            .len()
            .min(fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_SIZE);
        self.read_data(
            fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET,
            len,
            data,
        )
    }

    /// Read a specific HEK seed partition from OTP.
    /// index must be between 0 and 7.
    pub fn read_hek_seed(
        &self,
        index: usize,
        data: &mut [u8; HEK_PARTITION_SIZE],
    ) -> McuResult<()> {
        let offset = *HEK_OFFSETS
            .get(index)
            .ok_or(McuError::ROM_OTP_INVALID_DATA_ERROR)?;
        self.read_hek_partition(offset, data)
    }

    fn read_hek_partition(
        &self,
        partition_address: usize,
        data: &mut [u8; HEK_PARTITION_SIZE],
    ) -> McuResult<()> {
        self.read_data(partition_address, data.len(), data)
    }

    // -------------------------------------------------------------------------
    // Generic fuse entry read/write using generated FuseEntryInfo
    // -------------------------------------------------------------------------

    /// Read a fuse entry's logical value using its generated FuseEntryInfo.
    ///
    /// Reads raw bytes from OTP at the entry's byte_offset, then applies
    /// FuseLayout extraction to produce the logical value.
    /// Suitable for entries whose logical value fits in a single u32.
    pub fn read_entry(&self, entry: &FuseEntryInfo) -> McuResult<u32> {
        let layout = FuseLayout::from_generated(&entry.layout)
            .ok_or(McuError::ROM_UNSUPPORTED_FUSE_LAYOUT)?;
        let raw = self.read_word(entry.byte_offset / 4)?;
        crate::extract_single_fuse_value(layout, raw)
    }

    /// Read a fuse entry's raw bytes into a caller-provided buffer.
    ///
    /// Reads `entry.byte_size` bytes from OTP at `entry.byte_offset`.
    /// No layout extraction is applied — the caller gets the raw OTP data.
    /// Note that this will round up to the next multiple of 4 bytes to be read.
    pub fn read_entry_raw(&self, entry: &FuseEntryInfo, buf: &mut [u8]) -> McuResult<()> {
        let read_len = entry.byte_size.next_multiple_of(4);
        if buf.len() < read_len {
            return Err(McuError::ROM_OTP_INVALID_DATA_ERROR);
        }
        self.read_data(entry.byte_offset, read_len, buf)
    }

    /// Write a logical value to a fuse entry using its generated FuseEntryInfo.
    ///
    /// Applies FuseLayout encoding to produce the raw fuse value, then writes
    /// it to OTP via DAI. Suitable for entries whose value fits in a single u32.
    pub fn write_entry(&self, entry: &FuseEntryInfo, value: u32) -> McuResult<()> {
        let layout = FuseLayout::from_generated(&entry.layout)
            .ok_or(McuError::ROM_UNSUPPORTED_FUSE_LAYOUT)?;
        let raw = crate::write_single_fuse_value(layout, value)?;
        self.write_word(entry.byte_offset / 4, raw)?;
        Ok(())
    }

    pub fn write_data(&self, addr: usize, len: usize, data: &[u8]) -> McuResult<()> {
        if addr % 4 != 0 || len % 4 != 0 {
            return Err(McuError::ROM_OTP_INVALID_DATA_ERROR);
        }

        let mut offset = 0;
        while offset < len {
            let byte_addr = addr + offset;
            let granule_size = if is_64bit_granule(byte_addr) { 8 } else { 4 };
            let granule_addr = byte_addr & !(granule_size - 1);
            let granule_offset = byte_addr - granule_addr;
            let copy_len = (granule_size - granule_offset).min(len - offset);

            let mut granule = [0u8; 8];
            let available = data.len().saturating_sub(offset).min(copy_len);
            granule[granule_offset..granule_offset + available]
                .copy_from_slice(&data[offset..offset + available]);

            if granule_size == 8 {
                let dword = u64::from_le_bytes(granule);
                self.write_dword(granule_addr / 8, dword)?;
            } else {
                let mut word_bytes = [0u8; 4];
                word_bytes.copy_from_slice(&granule[0..4]);
                let word = u32::from_le_bytes(word_bytes);
                self.write_word(granule_addr / 4, word)?;
            }
            offset += copy_len;
        }
        Ok(())
    }

    /// Write a fuse entry's raw bytes from a caller-provided buffer.
    ///
    /// Writes `entry.byte_size` bytes to OTP at `entry.byte_offset`.
    /// Note that this will pad the length up to the next multiple of 4 bytes.
    pub fn write_entry_raw(&self, entry: &FuseEntryInfo, buf: &[u8]) -> McuResult<()> {
        if buf.len() < entry.byte_size {
            return Err(McuError::ROM_OTP_INVALID_DATA_ERROR);
        }
        let write_len = entry.byte_size.next_multiple_of(4);
        self.write_data(entry.byte_offset, write_len, buf)
    }

    /// Check if the HEK partition at the given offset is zeroized.
    pub fn is_hek_sanitized(&self, partition_address: usize) -> McuResult<bool> {
        // A partition is considered zeroized/sanitized if ALL bytes are 0xFF.
        // HEK partitions are 48 bytes: 32 (Seed) + 8 (Digest) + 8 (ZER marker).
        let mut partition_data = [0u8; fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_SIZE];
        self.read_hek_partition(partition_address, &mut partition_data)?;
        Ok(partition_data.iter().all(|&b| b == 0xFF))
    }

    /// Check if the HEK partition at the given offset is unused.
    pub fn is_hek_unused(&self, partition_address: usize) -> McuResult<bool> {
        let mut partition_data = [0u8; fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_SIZE];
        self.read_hek_partition(partition_address, &mut partition_data)?;
        let set_bit_count: u32 = partition_data.iter().map(|byte| byte.count_ones()).sum();
        Ok(set_bit_count == 0)
    }

    /// Compute the software digest of an OTP partition by reading its data
    /// (excluding the trailing 8-byte digest field) and hashing it with the
    /// PRESENT-based OTP digest algorithm.
    ///
    /// Uses streaming reads — only two OTP words are held in memory at a time,
    /// so this works for arbitrarily large partitions.
    ///
    /// Returns `McuError::ROM_OTP_INVALID_DATA_ERROR` if the partition does not
    /// have `sw_digest` set or if its size is too small to contain a digest.
    pub fn compute_sw_digest(
        &self,
        partition: &OtpPartitionInfo,
        iv: u64,
        cnst: u128,
    ) -> McuResult<u64> {
        let data_size = sw_digest_data_size(partition)?;

        // Read two words at a time from OTP, yielding u64 blocks to the
        // streaming digest. No large stack buffer required.
        let base_word = partition.byte_offset / 4;
        let num_u64_blocks = data_size / 8;
        let mut err: McuResult<()> = Ok(());

        let blocks = (0..num_u64_blocks).map_while(|block_idx| {
            if err.is_err() {
                return None;
            }
            let w0 = match self.read_word(base_word + block_idx * 2) {
                Ok(v) => v,
                Err(e) => {
                    err = Err(e);
                    return None;
                }
            };
            let w1 = match self.read_word(base_word + block_idx * 2 + 1) {
                Ok(v) => v,
                Err(e) => {
                    err = Err(e);
                    return None;
                }
            };
            Some(w0 as u64 | ((w1 as u64) << 32))
        });

        let digest = caliptra_mcu_otp_digest::otp_digest_iter(blocks, iv, cnst);
        err?;
        Ok(digest)
    }

    /// Compute and write the software digest for an OTP partition, locking it.
    ///
    /// Per the OTP spec, writing a non-zero value to the partition's digest
    /// entry via DAI locks write access to the partition after the next reset.
    ///
    /// This method:
    /// 1. Computes the 64-bit PRESENT-based digest over partition data
    /// 2. Writes it to the digest offset via DAI (64-bit write)
    /// 3. Reads it back and verifies
    ///
    /// Returns the computed digest on success.
    pub fn write_sw_digest_and_lock(
        &self,
        partition: &OtpPartitionInfo,
        iv: u64,
        cnst: u128,
    ) -> McuResult<u64> {
        let digest_offset = partition
            .digest_offset
            .ok_or(McuError::ROM_OTP_PARTITION_NO_DIGEST_OFFSET)?;

        let digest = self.compute_sw_digest(partition, iv, cnst)?;
        crate::println!(
            "[mcu-rom-otp] Writing SW digest {:#x} for partition '{}' at offset {:#x}",
            digest,
            partition.name,
            digest_offset
        );

        // The digest field always uses a 64-bit access granule in the DAI,
        // even for non-secret partitions whose data uses 32-bit granularity.
        self.write_dword(digest_offset / 8, digest)?;

        // Read back the digest using 64-bit granule (matching the write)
        let readback = self.read_dword(digest_offset / 8)?;
        if readback != digest {
            return Err(McuError::ROM_OTP_DIGEST_VERIFY_ERROR);
        }

        crate::println!(
            "[mcu-rom-otp] SW digest written and verified for '{}' - partition will lock on next reset",
            partition.name
        );
        Ok(digest)
    }

    pub fn burn_lifecycle_tokens(&self, tokens: &LifecycleHashedTokens) -> McuResult<()> {
        for (i, tokeni) in tokens.test_unlock.iter().enumerate() {
            crate::println!(
                "[mcu-rom-otp] Burning test_unlock{} token: {}",
                i,
                HexBytes(&tokeni.0)
            );
            self.burn_lifecycle_token(LC_TOKENS_OFFSET + i * LC_TOKEN_SIZE, tokeni)?;
        }

        crate::println!(
            "[mcu-rom-otp] Burning manuf token: {}",
            HexBytes(&tokens.manuf.0)
        );
        self.burn_lifecycle_token(
            LC_TOKENS_OFFSET + LC_TOKEN_MANUF_INDEX * LC_TOKEN_SIZE,
            &tokens.manuf,
        )?;

        crate::println!(
            "[mcu-rom-otp] Burning manuf_to_prod token: {}",
            HexBytes(&tokens.manuf_to_prod.0)
        );
        self.burn_lifecycle_token(
            LC_TOKENS_OFFSET + LC_TOKEN_MANUF_TO_PROD_INDEX * LC_TOKEN_SIZE,
            &tokens.manuf_to_prod,
        )?;

        crate::println!(
            "[mcu-rom-otp] Burning prod_to_prod_end token: {}",
            HexBytes(&tokens.prod_to_prod_end.0)
        );
        self.burn_lifecycle_token(
            LC_TOKENS_OFFSET + LC_TOKEN_PROD_TO_PROD_END_INDEX * LC_TOKEN_SIZE,
            &tokens.prod_to_prod_end,
        )?;

        crate::println!(
            "[mcu-rom-otp] Burning rma token: {}",
            HexBytes(&tokens.rma.0)
        );
        self.burn_lifecycle_token(
            LC_TOKENS_OFFSET + LC_TOKEN_RMA_INDEX * LC_TOKEN_SIZE,
            &tokens.rma,
        )?;

        crate::println!("[mcu-rom] Finalizing digest");
        self.finalize_digest(LC_TOKENS_OFFSET)?;
        Ok(())
    }

    fn burn_lifecycle_token(&self, addr: usize, token: &LifecycleHashedToken) -> McuResult<()> {
        let dword = u64::from_le_bytes(token.0[..8].try_into().unwrap());
        self.write_dword(addr / 8, dword)?;

        let dword = u64::from_le_bytes(token.0[8..16].try_into().unwrap());
        self.write_dword((addr + 8) / 8, dword)?;
        Ok(())
    }

    /// Read a multi-word fuse entry with layout decoding.
    ///
    /// Reads `entry.byte_size` bytes from OTP and applies the entry's layout
    /// to produce N decoded u32 words. Use this for entries larger than a
    /// single u32 (e.g., hash values with WordMajorityVote, large OneHot
    /// counters, etc.).
    pub fn read_entry_multi<const N: usize>(&self, entry: &FuseEntryInfo) -> McuResult<[u32; N]> {
        let layout = FuseLayout::from_generated(&entry.layout)
            .ok_or(McuError::ROM_UNSUPPORTED_FUSE_LAYOUT)?;
        let word_count = entry.byte_size / 4;
        // Read raw words into a caller-stack-friendly fixed buffer.
        // 64 words = 256 bytes covers all current OTP items.
        const MAX_RAW_WORDS: usize = 64;
        if word_count > MAX_RAW_WORDS {
            return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
        }
        let mut raw = [0u32; MAX_RAW_WORDS];
        let base_word = entry.byte_offset / 4;
        for i in 0..word_count {
            let word = raw.get_mut(i).ok_or(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)?;
            *word = self.read_word(base_word + i)?;
        }
        crate::extract_fuse_value::<N>(
            layout,
            raw.get(..word_count)
                .ok_or(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)?,
        )
    }

    /// Write a multi-word logical value to a fuse entry.
    ///
    /// Applies FuseLayout encoding to produce the raw fuse representation,
    /// then writes the resulting words to OTP via DAI.
    pub fn write_entry_multi<const N: usize, const M: usize>(
        &self,
        entry: &FuseEntryInfo,
        value: &[u32; N],
    ) -> McuResult<()> {
        let layout = FuseLayout::from_generated(&entry.layout)
            .ok_or(McuError::ROM_UNSUPPORTED_FUSE_LAYOUT)?;
        let raw: [u32; M] = crate::write_fuse_value::<N, M>(layout, value)?;
        let base_word = entry.byte_offset / 4;
        for i in 0..M {
            let w = raw.get(i).ok_or(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)?;
            self.write_word(base_word + i, *w)?;
        }
        Ok(())
    }

    /// Check if a field entropy slot is started in OTP memory.
    pub fn is_field_entropy_started(&self, slot: FieldEntropySlot) -> McuResult<bool> {
        let base_word = fuses::FIELD_ENTROPY_STATE.byte_offset / 4;
        let word_index = (slot as usize) * 3;
        let val = self.read_word(base_word + word_index)?;
        Ok(val == FieldEntropySlot::STARTED_MAGIC)
    }

    /// Check if a field entropy slot is finished in OTP memory.
    pub fn is_field_entropy_finished(&self, slot: FieldEntropySlot) -> McuResult<bool> {
        let base_word = fuses::FIELD_ENTROPY_STATE.byte_offset / 4;
        let word_index = (slot as usize) * 3 + 1;
        let val = self.read_word(base_word + word_index)?;
        Ok(val == FieldEntropySlot::FINISHED_MAGIC)
    }

    /// Check if a field entropy slot is zeroized in OTP memory.
    pub fn is_field_entropy_zeroized(&self, slot: FieldEntropySlot) -> McuResult<bool> {
        let base_word = fuses::FIELD_ENTROPY_STATE.byte_offset / 4;
        let word_index = (slot as usize) * 3 + 2;
        let val = self.read_word(base_word + word_index)?;
        Ok(val == FieldEntropySlot::ZEROIZED_MAGIC)
    }

    /// Mark a field entropy slot as started in OTP memory.
    pub fn mark_field_entropy_started(&self, slot: FieldEntropySlot) -> McuResult<()> {
        let base_word = fuses::FIELD_ENTROPY_STATE.byte_offset / 4;
        let word_index = (slot as usize) * 3;
        self.write_word(base_word + word_index, FieldEntropySlot::STARTED_MAGIC)?;
        Ok(())
    }

    /// Mark a field entropy slot as finished in OTP memory.
    pub fn mark_field_entropy_finished(&self, slot: FieldEntropySlot) -> McuResult<()> {
        let base_word = fuses::FIELD_ENTROPY_STATE.byte_offset / 4;
        let word_index = (slot as usize) * 3 + 1;
        self.write_word(base_word + word_index, FieldEntropySlot::FINISHED_MAGIC)?;
        Ok(())
    }

    /// Mark a field entropy slot as zeroized in OTP memory.
    pub fn mark_field_entropy_zeroized(&self, slot: FieldEntropySlot) -> McuResult<()> {
        let base_word = fuses::FIELD_ENTROPY_STATE.byte_offset / 4;
        let word_index = (slot as usize) * 3 + 2;
        self.write_word(base_word + word_index, FieldEntropySlot::ZEROIZED_MAGIC)?;
        Ok(())
    }
}

fn sw_digest_data_size(partition: &OtpPartitionInfo) -> McuResult<usize> {
    if !partition.sw_digest {
        return Err(McuError::ROM_OTP_PARTITION_NO_SW_DIGEST);
    }

    let partition_end = partition.byte_offset + partition.byte_size;
    let data_size = if let Some(digest_offset) = partition.digest_offset {
        if digest_offset < partition.byte_offset || digest_offset + DIGEST_SIZE > partition_end {
            return Err(McuError::ROM_OTP_PARTITION_TOO_SMALL_FOR_DIGEST);
        }
        digest_offset - partition.byte_offset
    } else {
        if partition.byte_size <= DIGEST_SIZE {
            return Err(McuError::ROM_OTP_PARTITION_TOO_SMALL_FOR_DIGEST);
        }
        partition.byte_size - DIGEST_SIZE
    };

    if data_size % 8 != 0 {
        return Err(McuError::ROM_OTP_PARTITION_NOT_8BYTE_ALIGNED_FOR_DIGEST);
    }

    Ok(data_size)
}

fn is_64bit_granule(byte_addr: usize) -> bool {
    matches!(
        byte_addr,
        // Secret partitions and digest/zeroization fields require 64-bit DAI granules.
        0x40..=0xf7
            | 0x2f8..=0x3b7
            | 0x418..=0x41f
            | 0x458..=0x45f
            | 0x7b8..=0x7bf
            | 0x890..=0xaa7
            | 0xca8..=0xcaf
            | 0xcd0..=0xcdf
            | 0xd00..=0xd0f
            | 0xd30..=0xd3f
            | 0xd60..=0xd6f
            | 0xd90..=0xd9f
            | 0xdc0..=0xdcf
            | 0xdf0..=0xdff
            | 0xe20..=0xe2f
    )
}

fn read_data_with(
    addr: usize,
    len: usize,
    data: &mut [u8],
    mut read_word: impl FnMut(usize) -> McuResult<u32>,
    mut read_dword: impl FnMut(usize) -> McuResult<u64>,
) -> McuResult<()> {
    let data = data
        .get_mut(..len)
        .ok_or(McuError::ROM_OTP_INVALID_DATA_ERROR)?;
    let mut offset = 0;
    while offset < len {
        let byte_addr = addr + offset;
        let granule_size = if is_64bit_granule(byte_addr) { 8 } else { 4 };
        let granule_addr = byte_addr & !(granule_size - 1);
        let granule_offset = byte_addr - granule_addr;
        let copy_len = (granule_size - granule_offset).min(len - offset);
        let mut granule = [0u8; 8];

        if granule_size == 8 {
            granule = read_dword(granule_addr / 8)?.to_le_bytes();
        } else {
            let word = read_word(granule_addr / 4)?.to_le_bytes();
            granule[0] = word[0];
            granule[1] = word[1];
            granule[2] = word[2];
            granule[3] = word[3];
        }

        for idx in 0..copy_len {
            let dst = data
                .get_mut(offset + idx)
                .ok_or(McuError::ROM_OTP_INVALID_DATA_ERROR)?;
            *dst = *granule
                .get(granule_offset + idx)
                .ok_or(McuError::ROM_OTP_INVALID_DATA_ERROR)?;
        }
        offset += copy_len;
    }
    Ok(())
}

/// Returns the FuseEntryInfo for the given vendor PK hash slot.
pub fn vendor_pk_hash_entry(index: usize) -> McuResult<&'static FuseEntryInfo> {
    match index {
        0 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_0),
        1 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_1),
        2 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_2),
        3 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_3),
        4 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_4),
        5 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_5),
        6 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_6),
        7 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_7),
        8 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_8),
        9 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_9),
        10 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_10),
        11 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_11),
        12 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_12),
        13 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_13),
        14 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_14),
        15 => Ok(fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_15),
        _ => Err(McuError::ROM_OTP_INVALID_DATA_ERROR),
    }
}

/// Returns the FuseEntryInfo for the given PQC key type slot.
pub fn pqc_key_type_entry(index: usize) -> McuResult<&'static FuseEntryInfo> {
    match index {
        0 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_0),
        1 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_1),
        2 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_2),
        3 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_3),
        4 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_4),
        5 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_5),
        6 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_6),
        7 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_7),
        8 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_8),
        9 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_9),
        10 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_10),
        11 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_11),
        12 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_12),
        13 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_13),
        14 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_14),
        15 => Ok(fuses::OTP_CPTRA_CORE_PQC_KEY_TYPE_15),
        _ => Err(McuError::ROM_OTP_INVALID_DATA_ERROR),
    }
}

/// Returns the FuseEntryInfo for the given vendor ECC revocation slot.
pub fn vendor_ecc_revocation_entry(index: usize) -> McuResult<&'static FuseEntryInfo> {
    match index {
        0 => Ok(fuses::VENDOR_ECC_REVOCATION_0),
        1 => Ok(fuses::VENDOR_ECC_REVOCATION_1),
        2 => Ok(fuses::VENDOR_ECC_REVOCATION_2),
        3 => Ok(fuses::VENDOR_ECC_REVOCATION_3),
        4 => Ok(fuses::VENDOR_ECC_REVOCATION_4),
        5 => Ok(fuses::VENDOR_ECC_REVOCATION_5),
        6 => Ok(fuses::VENDOR_ECC_REVOCATION_6),
        7 => Ok(fuses::VENDOR_ECC_REVOCATION_7),
        8 => Ok(fuses::VENDOR_ECC_REVOCATION_8),
        9 => Ok(fuses::VENDOR_ECC_REVOCATION_9),
        10 => Ok(fuses::VENDOR_ECC_REVOCATION_10),
        11 => Ok(fuses::VENDOR_ECC_REVOCATION_11),
        12 => Ok(fuses::VENDOR_ECC_REVOCATION_12),
        13 => Ok(fuses::VENDOR_ECC_REVOCATION_13),
        14 => Ok(fuses::VENDOR_ECC_REVOCATION_14),
        15 => Ok(fuses::VENDOR_ECC_REVOCATION_15),
        _ => Err(McuError::ROM_OTP_INVALID_DATA_ERROR),
    }
}

/// Returns the FuseEntryInfo for the given vendor LMS revocation slot.
pub fn vendor_lms_revocation_entry(index: usize) -> McuResult<&'static FuseEntryInfo> {
    match index {
        0 => Ok(fuses::VENDOR_LMS_REVOCATION_0),
        1 => Ok(fuses::VENDOR_LMS_REVOCATION_1),
        2 => Ok(fuses::VENDOR_LMS_REVOCATION_2),
        3 => Ok(fuses::VENDOR_LMS_REVOCATION_3),
        4 => Ok(fuses::VENDOR_LMS_REVOCATION_4),
        5 => Ok(fuses::VENDOR_LMS_REVOCATION_5),
        6 => Ok(fuses::VENDOR_LMS_REVOCATION_6),
        7 => Ok(fuses::VENDOR_LMS_REVOCATION_7),
        8 => Ok(fuses::VENDOR_LMS_REVOCATION_8),
        9 => Ok(fuses::VENDOR_LMS_REVOCATION_9),
        10 => Ok(fuses::VENDOR_LMS_REVOCATION_10),
        11 => Ok(fuses::VENDOR_LMS_REVOCATION_11),
        12 => Ok(fuses::VENDOR_LMS_REVOCATION_12),
        13 => Ok(fuses::VENDOR_LMS_REVOCATION_13),
        14 => Ok(fuses::VENDOR_LMS_REVOCATION_14),
        15 => Ok(fuses::VENDOR_LMS_REVOCATION_15),
        _ => Err(McuError::ROM_OTP_INVALID_DATA_ERROR),
    }
}

/// Returns the FuseEntryInfo for the given vendor MLDSA revocation slot.
pub fn vendor_mldsa_revocation_entry(index: usize) -> McuResult<&'static FuseEntryInfo> {
    match index {
        0 => Ok(fuses::VENDOR_MLDSA_REVOCATION_0),
        1 => Ok(fuses::VENDOR_MLDSA_REVOCATION_1),
        2 => Ok(fuses::VENDOR_MLDSA_REVOCATION_2),
        3 => Ok(fuses::VENDOR_MLDSA_REVOCATION_3),
        4 => Ok(fuses::VENDOR_MLDSA_REVOCATION_4),
        5 => Ok(fuses::VENDOR_MLDSA_REVOCATION_5),
        6 => Ok(fuses::VENDOR_MLDSA_REVOCATION_6),
        7 => Ok(fuses::VENDOR_MLDSA_REVOCATION_7),
        8 => Ok(fuses::VENDOR_MLDSA_REVOCATION_8),
        9 => Ok(fuses::VENDOR_MLDSA_REVOCATION_9),
        10 => Ok(fuses::VENDOR_MLDSA_REVOCATION_10),
        11 => Ok(fuses::VENDOR_MLDSA_REVOCATION_11),
        12 => Ok(fuses::VENDOR_MLDSA_REVOCATION_12),
        13 => Ok(fuses::VENDOR_MLDSA_REVOCATION_13),
        14 => Ok(fuses::VENDOR_MLDSA_REVOCATION_14),
        15 => Ok(fuses::VENDOR_MLDSA_REVOCATION_15),
        _ => Err(McuError::ROM_OTP_INVALID_DATA_ERROR),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldEntropySlot {
    Slot0 = 0,
    Slot1 = 1,
    Slot2 = 2,
    Slot3 = 3,
}

impl TryFrom<usize> for FieldEntropySlot {
    type Error = ();
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Slot0),
            1 => Ok(Self::Slot1),
            2 => Ok(Self::Slot2),
            3 => Ok(Self::Slot3),
            _ => Err(()),
        }
    }
}

impl FieldEntropySlot {
    pub const STARTED_MAGIC: u32 = 0x5354_5254; // "STRT"
    pub const FINISHED_MAGIC: u32 = 0x4649_4E53; // "FINS"
    pub const ZEROIZED_MAGIC: u32 = 0x5A45_524F; // "ZERO"
}

pub enum FieldEntropyState {
    Empty,
    Started,
    Finished,
    Zeroized,
}

impl FieldEntropyState {
    pub fn read(otp: &Otp, slot: FieldEntropySlot) -> McuResult<FieldEntropyState> {
        let started = otp.is_field_entropy_started(slot)?;
        let finished = otp.is_field_entropy_finished(slot)?;
        let zeroized = otp.is_field_entropy_zeroized(slot)?;
        if zeroized {
            Ok(FieldEntropyState::Zeroized)
        } else if started && !finished {
            Ok(FieldEntropyState::Started)
        } else if started && finished {
            Ok(FieldEntropyState::Finished)
        } else {
            Ok(FieldEntropyState::Empty)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sw_digest_data_size_uses_digest_offset_before_zer() {
        let partition = OtpPartitionInfo {
            name: "test_zeroizable_sw_digest",
            byte_offset: 0x100,
            byte_size: 0x30,
            secret: false,
            zeroizable: true,
            sw_digest: true,
            hw_digest: false,
            digest_offset: Some(0x120),
        };

        assert_eq!(sw_digest_data_size(&partition).unwrap(), 0x20);
    }

    #[test]
    fn test_is_64bit_granule_matches_partition_metadata() {
        let last_otp_byte = fuses::OTP_PARTITIONS
            .iter()
            .map(|partition| partition.byte_offset + partition.byte_size)
            .max()
            .unwrap();

        for byte_addr in 0..last_otp_byte {
            let expected = fuses::OTP_PARTITIONS.iter().any(|partition| {
                if byte_addr < partition.byte_offset
                    || byte_addr >= partition.byte_offset + partition.byte_size
                {
                    return false;
                }

                partition.secret
                    || partition
                        .digest_offset
                        .is_some_and(|offset| byte_addr >= offset && byte_addr < offset + 8)
                    || partition.zeroizable
                        && byte_addr >= partition.byte_offset + partition.byte_size - 8
            });
            assert_eq!(
                is_64bit_granule(byte_addr),
                expected,
                "incorrect granule for OTP byte offset {byte_addr:#x}"
            );
        }
    }

    #[test]
    fn test_read_hek_partition_uses_dwords_for_digest_and_zer() {
        let partition_address = fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_OFFSET;
        let digest = 0x1122_3344_5566_7788u64;
        let zer_marker = 0x99aa_bbcc_ddee_ff00u64;
        let mut otp_bytes = vec![0u8; partition_address + HEK_PARTITION_SIZE];
        for (idx, byte) in otp_bytes[partition_address..partition_address + HEK_SEED_SIZE]
            .iter_mut()
            .enumerate()
        {
            *byte = idx as u8;
        }
        otp_bytes[partition_address + HEK_SW_DIGEST_OFFSET
            ..partition_address + HEK_SW_DIGEST_OFFSET + HEK_SW_DIGEST_SIZE]
            .copy_from_slice(&digest.to_le_bytes());
        otp_bytes[partition_address + HEK_ZER_MARKER_OFFSET
            ..partition_address + HEK_ZER_MARKER_OFFSET + HEK_ZER_MARKER_SIZE]
            .copy_from_slice(&zer_marker.to_le_bytes());

        let mut data = [0u8; HEK_PARTITION_SIZE];
        let mut word_reads = 0;
        let mut dword_reads = [usize::MAX; 2];
        read_data_with(
            partition_address,
            data.len(),
            &mut data,
            |word_addr| {
                word_reads += 1;
                let byte_addr = word_addr * 4;
                Ok(u32::from_le_bytes(
                    otp_bytes[byte_addr..byte_addr + 4].try_into().unwrap(),
                ))
            },
            |dword_addr| {
                let idx = dword_reads
                    .iter()
                    .position(|addr| *addr == usize::MAX)
                    .unwrap();
                dword_reads[idx] = dword_addr;
                let byte_addr = dword_addr * 8;
                Ok(u64::from_le_bytes(
                    otp_bytes[byte_addr..byte_addr + 8].try_into().unwrap(),
                ))
            },
        )
        .unwrap();

        assert_eq!(
            data,
            otp_bytes[partition_address..partition_address + HEK_PARTITION_SIZE]
        );
        assert_eq!(word_reads, HEK_SEED_SIZE / 4);
        assert_eq!(
            dword_reads,
            [
                (partition_address + HEK_SW_DIGEST_OFFSET) / 8,
                (partition_address + HEK_ZER_MARKER_OFFSET) / 8,
            ]
        );
    }
}
