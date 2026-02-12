// Licensed under the Apache-2.0 license

use crate::{HexBytes, HexWord, StaticRef};
use core::fmt::Write;
use mcu_error::{McuError, McuResult};
use registers_generated::fuses;
use registers_generated::fuses::Fuses;
use registers_generated::otp_ctrl;
use tock_registers::interfaces::{Readable, Writeable};

use crate::{LifecycleHashedToken, LifecycleHashedTokens, LC_TOKENS_OFFSET};

// TODO: use the Lifecycle controller to read the Lifecycle state

// TODO: this error mask is dependent on the specific fuse map
const OTP_STATUS_ERROR_MASK: u32 = (1 << 22) - 1;
const OTP_CONSISTENCY_CHECK_PERIOD_MASK: u32 = 0x3ff_ffff;
const OTP_INTEGRITY_CHECK_PERIOD_MASK: u32 = 0x3ff_ffff;
const OTP_CHECK_TIMEOUT: u32 = 0x10_0000;
const OTP_PENDING_CHECK_MAX_ITERATIONS: u32 = 1_000_000;

// -------------------------------------------------------------------------
// Fuse field offsets within partitions
// These are offsets relative to the partition base address.
// -------------------------------------------------------------------------

const SVN_FMC_KEY_MANIFEST_SVN_OFFSET: usize = 0;
pub const SVN_RUNTIME_SVN_OFFSET: usize = 4;
pub const SVN_SOC_MANIFEST_SVN_OFFSET: usize = 20;
pub const SVN_SOC_MANIFEST_MAX_SVN_OFFSET: usize = 36;
const VENDOR_HASHES_MANUF_VENDOR_PK_HASH_0_OFFSET: usize = 0;
pub const VENDOR_HASHES_MANUF_PQC_KEY_TYPE_0_OFFSET: usize = 48;
const VENDOR_HASHES_PROD_OWNER_PK_HASH_OFFSET: usize = 0;
pub const VENDOR_REVOCATIONS_ECC_REVOCATION_0_OFFSET: usize = 12;
pub const VENDOR_REVOCATIONS_LMS_REVOCATION_0_OFFSET: usize = 16;
pub const VENDOR_REVOCATIONS_MLDSA_REVOCATION_0_OFFSET: usize = 20;
const SW_MANUF_ANTI_ROLLBACK_DISABLE_OFFSET: usize = 0;
pub const SW_MANUF_IDEVID_CERT_ATTR_OFFSET: usize = 4;
pub const SW_MANUF_IDEVID_MANUF_HSM_ID_OFFSET: usize = 104;
const SW_MANUF_SOC_STEPPING_ID_OFFSET: usize = 120;
pub const SW_MANUF_PROD_DEBUG_UNLOCK_PKS_OFFSET: usize = 124;
const SW_TEST_UNLOCK_MANUF_DEBUG_UNLOCK_TOKEN_OFFSET: usize = 0;
const LC_TOKEN_MANUF_INDEX: usize = 7;
const LC_TOKEN_MANUF_TO_PROD_INDEX: usize = 8;
const LC_TOKEN_PROD_TO_PROD_END_INDEX: usize = 9;
const LC_TOKEN_RMA_INDEX: usize = 10;

pub const PROD_DEBUG_UNLOCK_PK_SIZE: usize = 48;
const OWNER_PK_HASH_SIZE: usize = 48;
const VENDOR_PK_HASH_SIZE: usize = 48;
const RUNTIME_SVN_SIZE: usize = 16;
const SOC_MANIFEST_SVN_SIZE: usize = 16;
const IDEVID_CERT_ATTR_SIZE: usize = 96;
const IDEVID_MANUF_HSM_ID_SIZE: usize = 16;
const MANUF_DEBUG_UNLOCK_TOKEN_SIZE: usize = 64;
const LC_TOKEN_SIZE: usize = 16;

pub struct Otp {
    registers: StaticRef<otp_ctrl::regs::OtpCtrl>,
}

impl Otp {
    pub const fn new(registers: StaticRef<otp_ctrl::regs::OtpCtrl>) -> Self {
        Otp { registers }
    }

    pub fn volatile_lock(&self) {
        self.registers.vendor_pk_hash_volatile_lock.set(1);
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
        crate::println!("[mcu-rom-otp] OTP pending check exceeded maximum iterations");
        Err(McuError::ROM_OTP_PENDING_TIMEOUT)
    }

    pub fn check_error_and_idle(&self) -> McuResult<()> {
        if self.registers.otp_status.get() & OTP_STATUS_ERROR_MASK != 0 {
            crate::println!(
                "[mcu-rom-otp] OTP error: {}",
                self.registers.otp_status.get()
            );
            return Err(McuError::ROM_OTP_INIT_STATUS_ERROR);
        }

        // OTP DAI status should be idle
        if !self
            .registers
            .otp_status
            .is_set(otp_ctrl::bits::OtpStatus::DaiIdle)
        {
            crate::println!("[mcu-rom-otp] OTP not idle");
            return Err(McuError::ROM_OTP_INIT_NOT_IDLE);
        }

        Ok(())
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
        if data.len() < len || len % 4 != 0 {
            return Err(McuError::ROM_OTP_INVALID_DATA_ERROR);
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

        if let Some(err) = self.check_error() {
            crate::println!("Error reading fuses: {}", HexWord(err));
            return Err(McuError::ROM_OTP_READ_ERROR);
        }
        Ok(self.registers.dai_rdata_rf_direct_access_rdata_0.get())
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
        crate::println!("Write dword 0: {}", HexWord(data as u32));
        self.registers
            .dai_wdata_rf_direct_access_wdata_0
            .set((data) as u32);
        crate::println!("Write dword 1: {}", HexWord((data >> 32) as u32));
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

        if let Some(err) = self.check_error() {
            crate::println!("Error writing fuses: {}", HexWord(err));
            self.print_errors();
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

        if let Some(err) = self.check_error() {
            crate::println!("[mcu-rom] Error writing fuses: {}", HexWord(err));
            self.print_errors();
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

        if let Some(err) = self.check_error() {
            crate::println!("[mcu-rom] Error writing digest: {}", HexWord(err));
            self.print_errors();
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
        self.read_word(byte_offset / 4)
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
            let word = self.read_word(byte_offset / 4 + i)?;
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

    /// Read cptra_core_pqc_key_type_0 (4 bytes) from vendor_hashes_manuf_partition.
    pub fn read_cptra_core_pqc_key_type_0(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_data(
            fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET
                + VENDOR_HASHES_MANUF_PQC_KEY_TYPE_0_OFFSET,
            4,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_fmc_key_manifest_svn (4 bytes) from svn_partition.
    pub fn read_cptra_core_fmc_key_manifest_svn(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_data(
            fuses::SVN_PARTITION_BYTE_OFFSET + SVN_FMC_KEY_MANIFEST_SVN_OFFSET,
            4,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_vendor_pk_hash_0 (48 bytes) from vendor_hashes_manuf_partition.
    pub fn read_cptra_core_vendor_pk_hash_0(&self) -> McuResult<[u8; VENDOR_PK_HASH_SIZE]> {
        let mut data = [0u8; VENDOR_PK_HASH_SIZE];
        self.read_data(
            fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET
                + VENDOR_HASHES_MANUF_VENDOR_PK_HASH_0_OFFSET,
            VENDOR_PK_HASH_SIZE,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_runtime_svn (16 bytes) from svn_partition.
    pub fn read_cptra_core_runtime_svn(&self) -> McuResult<[u8; RUNTIME_SVN_SIZE]> {
        let mut data = [0u8; RUNTIME_SVN_SIZE];
        self.read_data(
            fuses::SVN_PARTITION_BYTE_OFFSET + SVN_RUNTIME_SVN_OFFSET,
            RUNTIME_SVN_SIZE,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_soc_manifest_svn (16 bytes) from svn_partition.
    pub fn read_cptra_core_soc_manifest_svn(&self) -> McuResult<[u8; SOC_MANIFEST_SVN_SIZE]> {
        let mut data = [0u8; SOC_MANIFEST_SVN_SIZE];
        self.read_data(
            fuses::SVN_PARTITION_BYTE_OFFSET + SVN_SOC_MANIFEST_SVN_OFFSET,
            SOC_MANIFEST_SVN_SIZE,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_soc_manifest_max_svn (4 bytes) from svn_partition.
    pub fn read_cptra_core_soc_manifest_max_svn(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_data(
            fuses::SVN_PARTITION_BYTE_OFFSET + SVN_SOC_MANIFEST_MAX_SVN_OFFSET,
            4,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_ss_manuf_debug_unlock_token (64 bytes) from sw_test_unlock_partition.
    pub fn read_cptra_ss_manuf_debug_unlock_token(
        &self,
    ) -> McuResult<[u8; MANUF_DEBUG_UNLOCK_TOKEN_SIZE]> {
        let mut data = [0u8; MANUF_DEBUG_UNLOCK_TOKEN_SIZE];
        self.read_data(
            fuses::SW_TEST_UNLOCK_PARTITION_BYTE_OFFSET
                + SW_TEST_UNLOCK_MANUF_DEBUG_UNLOCK_TOKEN_OFFSET,
            MANUF_DEBUG_UNLOCK_TOKEN_SIZE,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_ecc_revocation_0 (4 bytes) from vendor_revocations_prod_partition.
    pub fn read_cptra_core_ecc_revocation_0(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_data(
            fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_OFFSET
                + VENDOR_REVOCATIONS_ECC_REVOCATION_0_OFFSET,
            4,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_lms_revocation_0 (4 bytes) from vendor_revocations_prod_partition.
    pub fn read_cptra_core_lms_revocation_0(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_data(
            fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_OFFSET
                + VENDOR_REVOCATIONS_LMS_REVOCATION_0_OFFSET,
            4,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_mldsa_revocation_0 (4 bytes) from vendor_revocations_prod_partition.
    pub fn read_cptra_core_mldsa_revocation_0(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_data(
            fuses::VENDOR_REVOCATIONS_PROD_PARTITION_BYTE_OFFSET
                + VENDOR_REVOCATIONS_MLDSA_REVOCATION_0_OFFSET,
            4,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_ss_owner_pk_hash (48 bytes) from vendor_hashes_prod_partition.
    pub fn read_cptra_ss_owner_pk_hash(&self) -> McuResult<[u8; OWNER_PK_HASH_SIZE]> {
        let mut data = [0u8; OWNER_PK_HASH_SIZE];
        self.read_data(
            fuses::VENDOR_HASHES_PROD_PARTITION_BYTE_OFFSET
                + VENDOR_HASHES_PROD_OWNER_PK_HASH_OFFSET,
            OWNER_PK_HASH_SIZE,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_soc_stepping_id (4 bytes) from sw_manuf_partition.
    pub fn read_cptra_core_soc_stepping_id(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_data(
            fuses::SW_MANUF_PARTITION_BYTE_OFFSET + SW_MANUF_SOC_STEPPING_ID_OFFSET,
            4,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_anti_rollback_disable (4 bytes) from sw_manuf_partition.
    pub fn read_cptra_core_anti_rollback_disable(&self) -> McuResult<[u8; 4]> {
        let mut data = [0u8; 4];
        self.read_data(
            fuses::SW_MANUF_PARTITION_BYTE_OFFSET + SW_MANUF_ANTI_ROLLBACK_DISABLE_OFFSET,
            4,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_idevid_cert_idevid_attr (96 bytes) from sw_manuf_partition.
    pub fn read_cptra_core_idevid_cert_idevid_attr(
        &self,
    ) -> McuResult<[u8; IDEVID_CERT_ATTR_SIZE]> {
        let mut data = [0u8; IDEVID_CERT_ATTR_SIZE];
        self.read_data(
            fuses::SW_MANUF_PARTITION_BYTE_OFFSET + SW_MANUF_IDEVID_CERT_ATTR_OFFSET,
            IDEVID_CERT_ATTR_SIZE,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_core_idevid_manuf_hsm_identifier (16 bytes) from sw_manuf_partition.
    pub fn read_cptra_core_idevid_manuf_hsm_identifier(
        &self,
    ) -> McuResult<[u8; IDEVID_MANUF_HSM_ID_SIZE]> {
        let mut data = [0u8; IDEVID_MANUF_HSM_ID_SIZE];
        self.read_data(
            fuses::SW_MANUF_PARTITION_BYTE_OFFSET + SW_MANUF_IDEVID_MANUF_HSM_ID_OFFSET,
            IDEVID_MANUF_HSM_ID_SIZE,
            &mut data,
        )?;
        Ok(data)
    }

    /// Read cptra_ss_prod_debug_unlock_pks (index 0-7, each 48 bytes) from sw_manuf_partition.
    pub fn read_cptra_ss_prod_debug_unlock_pks(
        &self,
        index: usize,
    ) -> McuResult<[u8; PROD_DEBUG_UNLOCK_PK_SIZE]> {
        if index > 7 {
            return Err(McuError::ROM_OTP_INVALID_DATA_ERROR);
        }
        let mut data = [0u8; PROD_DEBUG_UNLOCK_PK_SIZE];
        let offset = fuses::SW_MANUF_PARTITION_BYTE_OFFSET
            + SW_MANUF_PROD_DEBUG_UNLOCK_PKS_OFFSET
            + (index * PROD_DEBUG_UNLOCK_PK_SIZE);
        self.read_data(offset, PROD_DEBUG_UNLOCK_PK_SIZE, &mut data)?;
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

    pub fn read_fuses(&self) -> McuResult<Fuses> {
        let mut fuses = Fuses::default();

        crate::println!("[mcu-rom-otp] Reading partitions");
        self.read_data(
            fuses::SW_TEST_UNLOCK_PARTITION_BYTE_OFFSET,
            fuses::SW_TEST_UNLOCK_PARTITION_BYTE_SIZE,
            &mut fuses.sw_test_unlock_partition,
        )?;
        self.read_data(
            fuses::SW_MANUF_PARTITION_BYTE_OFFSET,
            fuses::SW_MANUF_PARTITION_BYTE_SIZE,
            &mut fuses.sw_manuf_partition,
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
        // TODO: read these again when the offsets are fixed
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
            fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_SIZE,
            &mut fuses.cptra_ss_lock_hek_prod_0,
        )?;
        self.read_data(
            fuses::CPTRA_SS_LOCK_HEK_PROD_1_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_1_BYTE_SIZE,
            &mut fuses.cptra_ss_lock_hek_prod_1,
        )?;
        self.read_data(
            fuses::CPTRA_SS_LOCK_HEK_PROD_2_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_2_BYTE_SIZE,
            &mut fuses.cptra_ss_lock_hek_prod_2,
        )?;
        self.read_data(
            fuses::CPTRA_SS_LOCK_HEK_PROD_3_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_3_BYTE_SIZE,
            &mut fuses.cptra_ss_lock_hek_prod_3,
        )?;
        self.read_data(
            fuses::CPTRA_SS_LOCK_HEK_PROD_4_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_4_BYTE_SIZE,
            &mut fuses.cptra_ss_lock_hek_prod_4,
        )?;
        self.read_data(
            fuses::CPTRA_SS_LOCK_HEK_PROD_5_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_5_BYTE_SIZE,
            &mut fuses.cptra_ss_lock_hek_prod_5,
        )?;
        self.read_data(
            fuses::CPTRA_SS_LOCK_HEK_PROD_6_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_6_BYTE_SIZE,
            &mut fuses.cptra_ss_lock_hek_prod_6,
        )?;
        self.read_data(
            fuses::CPTRA_SS_LOCK_HEK_PROD_7_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_7_BYTE_SIZE,
            &mut fuses.cptra_ss_lock_hek_prod_7,
        )?;
        crate::println!("[mcu-rom-otp] Reading vendor non-secret production partition");
        self.read_data(
            fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET,
            fuses::VENDOR_NON_SECRET_PROD_PARTITION_BYTE_SIZE,
            &mut fuses.vendor_non_secret_prod_partition,
        )?;
        Ok(fuses)
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
}
