/*++

Licensed under the Apache-2.0 license.

File Name:

    riscv.rs

Abstract:

    File contains the common RISC-V code for MCU ROM

--*/

#![allow(clippy::empty_loop)]

use crate::flash::flash_partition::FlashPartition;
use crate::fuses::{DefaultVendorKeyPolicy, VendorKeyPolicy};
use crate::hil::FlashStorage;
use crate::otp::{Otp, PROD_DEBUG_UNLOCK_PK_ENTRIES};
use crate::ColdBoot;
use crate::FwBoot;
use crate::FwHitlessUpdate;
use crate::ImageVerifier;
use crate::LifecycleControllerState;
use crate::LifecycleHashedTokens;
use crate::LifecycleToken;
use crate::RomEnv;
use crate::WarmBoot;
use crate::{fatal_error, PqcKeyType};
use caliptra_api::mailbox::CmStableKeyType;
use core::fmt::Write;
use mcu_error::McuError;
use registers_generated::fuses;
use registers_generated::mci;
use registers_generated::mci::bits::SecurityState::DeviceLifecycle;
use registers_generated::soc;
use romtime::{HexWord, McuBootMilestones, StaticRef};
use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::{Readable, Writeable};

// values when setting in Caliptra
const MLDSA_CALIPTRA_VALUE: u8 = 1;
const LMS_CALIPTRA_VALUE: u8 = 3;
const OTP_DAI_IDLE_BIT_OFFSET: u32 = 22;
const OTP_DIRECT_ACCESS_CMD_REG_OFFSET: u32 = 0x60;

/// Trait for different boot flows (cold boot, warm reset, firmware update)
pub trait BootFlow {
    /// Execute the boot flow
    fn run(env: &mut RomEnv, params: RomParameters) -> !;
}

extern "C" {
    pub static MCU_MEMORY_MAP: mcu_config::McuMemoryMap;
    pub static MCU_STRAPS: mcu_config::McuStraps;
}

pub struct Soc {
    registers: StaticRef<soc::regs::Soc>,
}

impl Soc {
    pub const BOOT_FSM_DONE: u32 = 4;

    pub const fn new(registers: StaticRef<soc::regs::Soc>) -> Self {
        Soc { registers }
    }

    pub fn ready_for_runtime(&self) -> bool {
        self.registers
            .cptra_flow_status
            .is_set(soc::bits::CptraFlowStatus::ReadyForRuntime)
    }

    pub fn fw_ready(&self) -> bool {
        self.registers.ss_generic_fw_exec_ctrl[0].get() & (1 << 2) != 0
    }

    pub fn flow_status(&self) -> u32 {
        self.registers.cptra_flow_status.get()
    }

    pub fn boot_fsm_ps(&self) -> u32 {
        self.registers
            .cptra_flow_status
            .read(soc::bits::CptraFlowStatus::BootFsmPs)
    }

    pub fn wait_for_bootfsm_done(&self, timeout_cycles: u64) {
        let start = romtime::mcycle();
        while self.boot_fsm_ps() != Self::BOOT_FSM_DONE {
            if self.cptra_fw_fatal_error() {
                romtime::println!(
                    "[mcu-rom] Caliptra reported a fatal error during boot FSM transition"
                );
                fatal_error(McuError::ROM_SOC_CALIPTRA_FATAL_ERROR_BEFORE_FW_READY);
            }
            if romtime::mcycle() - start > timeout_cycles {
                romtime::println!(
                    "[mcu-rom] Caliptra Core boot FSM timed out waiting for BOOT_DONE"
                );
                fatal_error(McuError::ROM_BOOTFSM_TIMEOUT);
            }
        }
    }

    pub fn ready_for_mbox(&self) -> bool {
        self.registers
            .cptra_flow_status
            .is_set(soc::bits::CptraFlowStatus::ReadyForMbProcessing)
    }

    pub fn ready_for_fuses(&self) -> bool {
        self.registers
            .cptra_flow_status
            .is_set(soc::bits::CptraFlowStatus::ReadyForFuses)
    }

    pub fn cptra_fw_fatal_error(&self) -> bool {
        self.registers.cptra_fw_error_fatal.get() != 0
    }

    pub fn check_hw_errors(&self) {
        let hw_error = self.registers.cptra_hw_error_fatal.extract();
        if hw_error.is_set(soc::bits::CptraHwErrorFatal::IccmEccUnc) {
            romtime::println!("[mcu-rom] Caliptra reported an ICCM ECC uncorrectable error");
            fatal_error(McuError::ROM_SOC_ICCM_ECC_UNC);
        }
        if hw_error.is_set(soc::bits::CptraHwErrorFatal::DccmEccUnc) {
            romtime::println!("[mcu-rom] Caliptra reported a DCCM ECC uncorrectable error");
            fatal_error(McuError::ROM_SOC_DCCM_ECC_UNC);
        }
    }

    pub fn set_cptra_wdt_cfg(&self, index: usize, value: u32) {
        self.registers.cptra_wdt_cfg[index].set(value);
    }

    pub fn set_cptra_mbox_valid_axi_user(&self, index: usize, value: u32) {
        if index >= self.registers.cptra_mbox_valid_axi_user.len() {
            fatal_error(McuError::ROM_SOC_MBOX_USER_OUT_OF_RANGE)
        }
        self.registers.cptra_mbox_valid_axi_user[index].set(value);
    }

    pub fn set_cptra_mbox_axi_user_lock(&self, index: usize, value: u32) {
        if index >= self.registers.cptra_mbox_valid_axi_user.len() {
            fatal_error(McuError::ROM_SOC_MBOX_USER_LOCK_OUT_OF_RANGE)
        }
        self.registers.cptra_mbox_axi_user_lock[index].set(value);
    }

    pub fn set_cptra_fuse_valid_axi_user(&self, value: u32) {
        self.registers.cptra_fuse_valid_axi_user.set(value);
    }

    pub fn set_cptra_fuse_axi_user_lock(&self, value: u32) {
        self.registers.cptra_fuse_axi_user_lock.set(value);
    }

    pub fn set_cptra_trng_valid_axi_user(&self, value: u32) {
        self.registers.cptra_trng_valid_axi_user.set(value);
    }

    pub fn set_cptra_trng_axi_user_lock(&self, value: u32) {
        self.registers.cptra_trng_axi_user_lock.set(value);
    }

    pub fn set_ss_caliptra_dma_axi_user(&self, value: u32) {
        self.registers.ss_caliptra_dma_axi_user.set(value);
    }

    #[inline(never)]
    pub fn populate_fuses(&self, otp: &Otp, mci: &romtime::Mci, params: &RomParameters) {
        // secret fuses are populated by a hardware state machine, so we can skip those

        // UDS partition base address. (FE offset is calculated automatically by Caliptra ROM.)
        let offset = fuses::SECRET_MANUF_PARTITION_BYTE_OFFSET;
        romtime::println!(
            "[mcu-fuse-write] Setting UDS/FE base address to {:x}",
            offset
        );
        self.registers.ss_uds_seed_base_addr_l.set(offset as u32);
        self.registers.ss_uds_seed_base_addr_h.set(0);

        romtime::println!(
            "[mcu-fuse-write] Setting UDS/FE DAI idle bit offset to {} and direct access cmd reg offset to {}",
            OTP_DAI_IDLE_BIT_OFFSET,
            OTP_DIRECT_ACCESS_CMD_REG_OFFSET
        );
        self.registers.ss_strap_generic[0].set(OTP_DAI_IDLE_BIT_OFFSET << 16);
        self.registers.ss_strap_generic[1].set(OTP_DIRECT_ACCESS_CMD_REG_OFFSET);

        // Select the vendor public key slot to use.
        let default_policy = DefaultVendorKeyPolicy::new();
        let policy = params.vendor_key_policy.unwrap_or(&default_policy);
        let selected_index = policy
            .select_key(otp)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_PK_HASH_SELECTION_FAILED));
        romtime::println!(
            "[mcu-fuse-write] Selected vendor PK slot {}",
            selected_index
        );

        // PQC Key Type.
        let pqc_type = otp
            .read_pqc_key_type(selected_index)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        let pqc_caliptra_val = match pqc_type {
            PqcKeyType::MLDSA => MLDSA_CALIPTRA_VALUE,
            PqcKeyType::LMS => LMS_CALIPTRA_VALUE,
        };
        self.registers
            .fuse_pqc_key_type
            .set(pqc_caliptra_val as u32);
        romtime::println!(
            "[mcu-fuse-write] Setting vendor PQC type to {}",
            pqc_caliptra_val
        );

        // FMC Key Manifest SVN.
        let svn = otp
            .read_u32_at(fuses::OTP_CPTRA_CORE_FMC_KEY_MANIFEST_SVN.byte_offset)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        self.registers.fuse_fmc_key_manifest_svn.set(svn);

        // Vendor PK Hash.
        romtime::print!("[mcu-fuse-write] Writing fuse key vendor PK hash: ");
        let mut hash_buf = [0u8; 48];
        otp.read_vendor_pk_hash(selected_index, &mut hash_buf)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        for (i, word_bytes) in hash_buf.chunks_exact(4).enumerate() {
            let word = u32::from_le_bytes(word_bytes.try_into().unwrap());
            romtime::print!("{}", HexWord(word));
            self.registers.fuse_vendor_pk_hash[i].set(word);
        }
        romtime::println!("");

        // Runtime SVN.
        for i in 0..self.registers.fuse_runtime_svn.len() {
            let word = otp
                .read_u32_at(fuses::OTP_CPTRA_CORE_RUNTIME_SVN.byte_offset + i * 4)
                .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
            self.registers.fuse_runtime_svn[i].set(word);
        }

        // SoC Manifest SVN.
        for i in 0..self.registers.fuse_soc_manifest_svn.len() {
            let word = otp
                .read_u32_at(fuses::OTP_CPTRA_CORE_SOC_MANIFEST_SVN.byte_offset + i * 4)
                .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
            self.registers.fuse_soc_manifest_svn[i].set(word);
        }

        // SoC Manifest Max SVN.
        let word = otp
            .read_u32_at(fuses::OTP_CPTRA_CORE_SOC_MANIFEST_MAX_SVN.byte_offset)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        self.registers.fuse_soc_manifest_max_svn.set(word);

        // Manuf Debug Unlock Token.
        for i in 0..self.registers.fuse_manuf_dbg_unlock_token.len() {
            let word = otp
                .read_u32_at(fuses::OTP_CPTRA_SS_MANUF_DEBUG_UNLOCK_TOKEN.byte_offset + i * 4)
                .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
            self.registers.fuse_manuf_dbg_unlock_token[i].set(word);
        }

        // TODO: vendor-specific fuses when those are supported
        // Load Owner ECC/LMS/MLDSA revocation CSRs.
        // ECC Revocation.
        let word = otp
            .read_vendor_ecc_revocation(selected_index)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        self.registers.fuse_ecc_revocation.set(word);

        // LMS Revocation.
        let word = otp
            .read_vendor_lms_revocation(selected_index)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        self.registers.fuse_lms_revocation.set(word);

        // MLDSA Revocation.
        let word = otp
            .read_vendor_mldsa_revocation(selected_index)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        self.registers.fuse_mldsa_revocation.set(word);

        // Owner PK Hash is written separately after Device Ownership Transfer flow.
        // See set_owner_pk_hash() method.

        // TODO: load HEK Seed CSRs.
        // SoC Stepping ID (only 16-bits are relevant).
        let word = otp
            .read_u32_at(fuses::OTP_CPTRA_CORE_SOC_STEPPING_ID.byte_offset)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        let soc_stepping_id = word & 0xFFFF;
        self.registers
            .fuse_soc_stepping_id
            .write(soc::bits::FuseSocSteppingId::SocSteppingId.val(soc_stepping_id));

        // Anti Rollback Disable. - read single word
        let word = otp
            .read_u32_at(fuses::OTP_CPTRA_CORE_ANTI_ROLLBACK_DISABLE.byte_offset)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        self.registers
            .fuse_anti_rollback_disable
            .write(soc::bits::FuseAntiRollbackDisable::Dis.val(word));

        // IDevID Cert Attr.
        for i in 0..self.registers.fuse_idevid_cert_attr.len() {
            let word = otp
                .read_u32_at(fuses::OTP_CPTRA_CORE_IDEVID_CERT_IDEVID_ATTR.byte_offset + i * 4)
                .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
            self.registers.fuse_idevid_cert_attr[i].set(word);
        }

        // IDevID Manuf HSM ID.
        for i in 0..self.registers.fuse_idevid_manuf_hsm_id.len() {
            let word = otp
                .read_u32_at(fuses::OTP_CPTRA_CORE_IDEVID_MANUF_HSM_IDENTIFIER.byte_offset + i * 4)
                .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
            self.registers.fuse_idevid_manuf_hsm_id[i].set(word);
        }

        // Prod Debug Unlock Public Key Hashes - read 96 words (384 bytes = 8 x 48 bytes) directly into MCI
        // Each of the 8 hashes is 48 bytes (12 words)
        for hash_idx in 0..8 {
            let entry = PROD_DEBUG_UNLOCK_PK_ENTRIES
                .get(hash_idx)
                .unwrap_or_else(|| fatal_error(McuError::ROM_OTP_READ_ERROR));
            let hash_base_offset = entry.byte_offset;
            for word_idx in 0..12 {
                let word = otp
                    .read_u32_at(hash_base_offset + word_idx * 4)
                    .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
                let reg_idx = hash_idx * 12 + word_idx;
                mci.registers.mci_reg_prod_debug_unlock_pk_hash_reg[reg_idx].set(word);
            }
        }
        // Set the debug enablement masks for: DFT, HW Debug, Prod Debug.
        //
        // Note: this enables all 8 debug levels (supported by the 8 prod debug
        // unlock public key hash slots in the reference fuse map) to unlock
        // DFT, HW debug, and prod debug access. Integrators should change this
        // based on their integration.
        mci.registers.mci_reg_soc_dft_en[0].set(0x000000FF);
        mci.registers.mci_reg_soc_dft_en[1].set(0x00000000);
        mci.registers.mci_reg_soc_hw_debug_en[0].set(0x000000FF);
        mci.registers.mci_reg_soc_hw_debug_en[1].set(0x00000000);
        mci.registers.mci_reg_soc_prod_debug_state[0].set(0x000000FF);
        mci.registers.mci_reg_soc_prod_debug_state[1].set(0x00000000);
    }

    pub fn set_axi_users(&self, users: AxiUsers) {
        let AxiUsers {
            mbox_users,
            fuse_user,
            trng_user,
            dma_user,
        } = users;

        for (i, user) in mbox_users.iter().enumerate() {
            if let Some(user) = *user {
                romtime::println!(
                    "[mcu-rom] Setting Caliptra mailbox user {i} to {}",
                    HexWord(user)
                );
                self.set_cptra_mbox_valid_axi_user(i, user);
                romtime::println!("[mcu-rom] Locking Caliptra mailbox user {i}");
                self.set_cptra_mbox_axi_user_lock(i, 1);
            }
        }

        if fuse_user != 0 {
            romtime::println!("[mcu-rom] Setting fuse user");
            self.set_cptra_fuse_valid_axi_user(fuse_user);
            romtime::println!("[mcu-rom] Locking fuse user");
            self.set_cptra_fuse_axi_user_lock(1);
        }
        if trng_user != 0 {
            romtime::println!("[mcu-rom] Setting TRNG user");
            self.set_cptra_trng_valid_axi_user(trng_user);
            romtime::println!("[mcu-rom] Locking TRNG user");
            self.set_cptra_trng_axi_user_lock(1);
        }
        if dma_user != 0 {
            romtime::println!("[mcu-rom] Setting DMA user");
            self.set_ss_caliptra_dma_axi_user(dma_user);
        }
    }

    /// Sets the owner public key hash in Caliptra's SoC interface registers.
    ///
    /// This is called after Device Ownership Transfer (DOT) flow completes to set
    /// the owner PK hash from either the DOT blob or the fuses.
    ///
    /// # Arguments
    /// * `owner_pk_hash` - The owner public key hash to set.
    pub fn set_owner_pk_hash(&self, owner_pk_hash: &crate::fuses::OwnerPkHash) {
        romtime::print!("[mcu-fuse-write] Writing owner PK hash: ");
        for (i, word) in owner_pk_hash.0.iter().enumerate() {
            romtime::print!("{}", HexWord(*word));
            self.registers.cptra_owner_pk_hash[i].set(*word);
        }
        romtime::println!("");
    }

    /// Locks the owner public key hash register.
    ///
    /// Once locked, the owner PK hash cannot be modified until the next reset.
    pub fn lock_owner_pk_hash(&self) {
        self.registers.cptra_owner_pk_hash_lock.set(1);
    }

    pub fn fuse_write_done(&self) {
        self.registers.cptra_fuse_wr_done.set(1);
    }

    /// Waits for Caliptra to indicate MCU firmware is ready through the `NotifCptraMcuResetReqSts`
    /// interrupt.
    pub fn wait_for_firmware_ready(&self, mci: &romtime::Mci) {
        let notif0 = &mci.registers.intr_block_rf_notif0_internal_intr_r;
        // TODO(zhalvorsen): use interrupt instead of fw_exec_ctrl register when the emulator supports it
        // Wait for a reset request from Caliptra
        while !self.fw_ready() {
            if self.cptra_fw_fatal_error() {
                romtime::println!("[mcu-rom] Caliptra reported a fatal error");
                fatal_error(McuError::ROM_SOC_CALIPTRA_FATAL_ERROR_BEFORE_FW_READY);
            }
            self.check_hw_errors();
        }
        // Clear the reset request interrupt
        notif0.modify(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts::SET);
    }

    /// Configure the Caliptra iTRNG parameters.
    pub fn configure_itrng(&self, args: CptraItrngArgs) {
        let bypass_mode = u32::from(args.bypass_mode) << 31;
        let window_size = u32::from(args.window_size);
        self.registers.ss_strap_generic[2].set(bypass_mode | window_size);
        self.registers
            .cptra_i_trng_entropy_config_0
            .set(args.config0);
        self.registers
            .cptra_i_trng_entropy_config_1
            .set(args.config1);
    }
}

/// Caliptra iTRNG configuration parameters.
///
/// See the [spec](https://chipsalliance.github.io/caliptra-web/docs/2.1/firmware/rom_spec.html#entropy-source-configuration-registers)
/// for more details.
pub struct CptraItrngArgs {
    pub bypass_mode: bool,
    pub window_size: u16,
    pub config0: u32,
    pub config1: u32,
}

/// Number of users supported by the MCU MBOX ACL mechanism.
pub const MCU_MBOX_USERS: usize = 5;

/// Structure to hold expected values for MCU mailbox AXI user configuration.
/// Used for verification after SS_CONFIG_DONE_STICKY is set.
#[derive(Debug, Default, Clone)]
pub struct McuMboxAxiUserConfig {
    /// Expected values for MBOX0 valid AXI users (None = not configured)
    pub mbox0_users: [Option<u32>; MCU_MBOX_USERS],
    /// Expected values for MBOX1 valid AXI users (None = not configured)
    pub mbox1_users: [Option<u32>; MCU_MBOX_USERS],
    /// Expected lock status for MBOX0 AXI users
    pub mbox0_locks: [bool; MCU_MBOX_USERS],
    /// Expected lock status for MBOX1 AXI users
    pub mbox1_locks: [bool; MCU_MBOX_USERS],
}

/// Configures MCU mailbox AXI users in MCI and returns the configuration for later verification.
pub fn configure_mcu_mbox_axi_users(
    mci: &romtime::Mci,
    mbox0_axi_users: &[u32; 5],
    mbox1_axi_users: &[u32; 5],
) -> McuMboxAxiUserConfig {
    let mut config = McuMboxAxiUserConfig::default();

    // Configure MBOX0 AXI users
    for (i, user) in mbox0_axi_users.iter().enumerate() {
        // skip unconfigured users and avoid impossible panics
        if *user != 0 && i < config.mbox0_users.len() && i < config.mbox0_locks.len() {
            romtime::println!(
                "[mcu-rom] Setting MCI mailbox 0 user {} to {}",
                i,
                HexWord(*user)
            );
            config.mbox0_users[i] = Some(*user);
            config.mbox0_locks[i] = true;
            mci.write_mbox0_valid_axi_user(i, *user);
            mci.lock_mbox0_axi_user(i);
        }
    }

    // Configure MBOX1 AXI users
    for (i, user) in mbox1_axi_users.iter().enumerate() {
        // skip unconfigured users and avoid impossible panics
        if *user != 0 && i < config.mbox1_users.len() && i < config.mbox1_locks.len() {
            romtime::println!(
                "[mcu-rom] Setting MCI mailbox 1 user {} to {}",
                i,
                HexWord(*user)
            );
            config.mbox1_users[i] = Some(*user);
            config.mbox1_locks[i] = true;
            mci.write_mbox1_valid_axi_user(i, *user);
            mci.lock_mbox1_axi_user(i);
        }
    }

    config
}

/// Verifies that the production debug unlock PK hashes haven't been tampered with
/// after SS_CONFIG_DONE_STICKY is set.
///
/// This function compares the current MCI register values against the expected values
/// read from OTP word-by-word to minimize stack usage.
#[inline(never)]
pub fn verify_prod_debug_unlock_pk_hash(mci: &romtime::Mci, otp: &Otp) -> Result<(), McuError> {
    // Verify length matches: 384 bytes = 96 u32 words
    let pk_hash_len = mci.prod_debug_unlock_pk_hash_len();
    if pk_hash_len != 96 {
        romtime::println!(
            "[mcu-rom] PK hash length mismatch: expected 96, got {}",
            pk_hash_len
        );
        return Err(McuError::ROM_SOC_PK_HASH_VERIFY_FAILED);
    }

    // Compare word-by-word to minimize stack usage
    // Each of the 8 hashes is 48 bytes (12 words)
    let mut mismatch = false;
    for hash_idx in 0..8 {
        let entry = PROD_DEBUG_UNLOCK_PK_ENTRIES
            .get(hash_idx)
            .ok_or(McuError::ROM_SOC_PK_HASH_VERIFY_FAILED)?;
        let hash_base_offset = entry.byte_offset;
        for word_idx in 0..12 {
            let reg_idx = hash_idx * 12 + word_idx;
            let expected = otp
                .read_u32_at(hash_base_offset + word_idx * 4)
                .map_err(|_| McuError::ROM_SOC_PK_HASH_VERIFY_FAILED)?;
            let actual = mci.read_prod_debug_unlock_pk_hash(reg_idx).unwrap_or(0);
            // Use bitwise OR to accumulate mismatches (constant-time)
            mismatch |= expected != actual;
        }
    }

    if mismatch {
        romtime::println!("[mcu-rom] Prod debug unlock PK hash verification failed");
        return Err(McuError::ROM_SOC_PK_HASH_VERIFY_FAILED);
    }
    romtime::println!("[mcu-rom] Prod debug unlock PK hash verification passed");
    Ok(())
}

/// Verifies that the MCU mailbox AXI user configuration hasn't been tampered with
/// after SS_CONFIG_DONE_STICKY is set.
pub fn verify_mcu_mbox_axi_users(
    mci: &romtime::Mci,
    expected: &McuMboxAxiUserConfig,
) -> Result<(), McuError> {
    // Verify MBOX0 AXI users and locks
    for (i, (expected_user, expected_lock)) in expected
        .mbox0_users
        .iter()
        .zip(expected.mbox0_locks.iter())
        .enumerate()
    {
        // Verify AXI user value if configured
        if let Some(expected_val) = *expected_user {
            let actual_val = mci.read_mbox0_valid_axi_user(i).unwrap_or(0);
            if expected_val != actual_val {
                romtime::println!(
                    "[mcu-rom] MCU mailbox 0 user {} verification failed: expected {}, got {}",
                    i,
                    HexWord(expected_val),
                    HexWord(actual_val)
                );
                return Err(McuError::ROM_SOC_MCU_MBOX_AXI_USER_VERIFY_FAILED);
            }
        }
        // Verify lock status matches expected
        let actual_locked = mci.read_mbox0_axi_user_lock(i).unwrap_or(false);
        if *expected_lock != actual_locked {
            romtime::println!(
                "[mcu-rom] MCU mailbox 0 user {} lock verification failed: expected {}, got {}",
                i,
                expected_lock,
                actual_locked
            );
            return Err(McuError::ROM_SOC_MCU_MBOX_AXI_USER_VERIFY_FAILED);
        }
    }

    // Verify MBOX1 AXI users and locks
    for (i, (expected_user, expected_lock)) in expected
        .mbox1_users
        .iter()
        .zip(expected.mbox1_locks.iter())
        .enumerate()
    {
        // Verify AXI user value if configured
        if let Some(expected_val) = *expected_user {
            let actual_val = mci.read_mbox1_valid_axi_user(i).unwrap_or(0);
            if expected_val != actual_val {
                romtime::println!(
                    "[mcu-rom] MCU mailbox 1 user {} verification failed: expected {}, got {}",
                    i,
                    HexWord(expected_val),
                    HexWord(actual_val)
                );
                return Err(McuError::ROM_SOC_MCU_MBOX_AXI_USER_VERIFY_FAILED);
            }
        }
        // Verify lock status matches expected
        let actual_locked = mci.read_mbox1_axi_user_lock(i).unwrap_or(false);
        if *expected_lock != actual_locked {
            romtime::println!(
                "[mcu-rom] MCU mailbox 1 user {} lock verification failed: expected {}, got {}",
                i,
                expected_lock,
                actual_locked
            );
            return Err(McuError::ROM_SOC_MCU_MBOX_AXI_USER_VERIFY_FAILED);
        }
    }

    romtime::println!("[mcu-rom] MCU mailbox AXI user verification passed");
    Ok(())
}

/// Policy controlling whether DOT backup-blob recovery is attempted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DotRecoveryPolicy {
    /// Attempt backup blob recovery (default).
    BackupBlob,
    /// Do not attempt any recovery.
    None,
}

impl Default for DotRecoveryPolicy {
    fn default() -> Self {
        Self::BackupBlob
    }
}

#[derive(Default)]
pub struct RomParameters<'a> {
    pub lifecycle_transition: Option<(LifecycleControllerState, LifecycleToken)>,
    pub burn_lifecycle_tokens: Option<LifecycleHashedTokens>,
    pub flash_partition_driver: Option<&'a mut FlashPartition<'a>>,
    /// Whether or not to program field entropy after booting Caliptra runtime firmware
    pub program_field_entropy: [bool; 4],
    pub mcu_image_header_size: usize,
    pub mcu_image_verifier: Option<&'a dyn ImageVerifier>,
    /// The stable key type to use for DOT operations (IDevID or LDevID; IDevID is the default if not specified).
    pub dot_stable_key_type: Option<CmStableKeyType>,
    /// Flash storage interface for DOT blob.
    pub dot_flash: Option<&'a dyn FlashStorage>,
    /// Recovery handler for recovering from corrupted DOT blob in ODD state (backup blob flow).
    pub dot_recovery_handler: Option<&'a dyn crate::DotRecoveryHandler>,
    /// Whether to attempt backup-blob recovery.
    pub dot_recovery_policy: DotRecoveryPolicy,
    /// Whether to check for and process firmware manifest DOT commands.
    /// When true, the ROM will look for a FwManifestDotSection at the start
    /// of MCU SRAM during FwBoot and process any DOT commands found.
    /// Default: false (opt-in by platform integrators).
    pub fw_manifest_dot_enabled: bool,
    /// Recovery/override transport for DOT challenge/response protocol (e.g., MCI mbox0, I3C).
    pub dot_recovery_transport: Option<&'a dyn crate::RecoveryTransport>,
    /// DOT recovery/override watchdog timeout in clock cycles. If non-zero,
    /// the MCU watchdog is configured with this value before waiting for
    /// mbox0 commands during recovery or override. 0 = no watchdog.
    pub dot_recovery_wdt_timeout: u64,
    pub otp_enable_integrity_check: bool,
    pub otp_enable_consistency_check: bool,
    pub otp_check_timeout_override: Option<u32>,
    /// Request flash boot (AXI recovery bypass).
    pub request_flash_boot: bool,
    /// By default, we will set recovery status as successful after loading MCU firmware.
    /// Set this to true if you want to leave recovery status as open for further firmware image loading.
    /// Note that in 2.0, Caliptra already sets recovery status as successful so there may be a race
    /// condition depending on when a BMC reads the recovery status.
    pub recovery_status_open: bool,
    /// Valid AXI users for Caliptra mailbox. 0 values are ignored.
    pub cptra_mbox_axi_users: [u32; 5],
    /// Valid AXI user for Caliptra fuse registers. 0 = don't configure.
    pub cptra_fuse_axi_user: u32,
    /// Valid AXI user for Caliptra TRNG. 0 = don't configure.
    pub cptra_trng_axi_user: u32,
    /// Valid AXI user for Caliptra DMA. 0 = don't configure.
    pub cptra_dma_axi_user: u32,
    /// Valid AXI users for MCI mailbox 0. 0 values are ignored.
    pub mci_mbox0_axi_users: [u32; 5],
    /// Valid AXI users for MCI mailbox 1. 0 values are ignored.
    pub mci_mbox1_axi_users: [u32; 5],
    /// Policy for selecting the vendor public key slot.
    pub vendor_key_policy: Option<&'a dyn VendorKeyPolicy>,
    /// OTP digest IV and finalization constant (platform-specific RTL constants).
    /// Required to use `Otp::compute_sw_digest` and `Otp::write_sw_digest_and_lock`.
    pub otp_digest_iv: Option<u64>,
    pub otp_digest_const: Option<u128>,
    /// Caliptra entropy bypass mode. See [spec](https://chipsalliance.github.io/caliptra-web/docs/2.1/firmware/rom_spec.html#entropy-source-configuration-registers)
    /// for more details.
    pub itrng_entropy_bypass_mode: bool,
    pub stash_rom_digest: Option<bool>,
}

#[inline(always)]
pub fn rom_start(params: RomParameters) {
    romtime::println!("[mcu-rom] Hello from ROM");

    // Create ROM environment with all peripherals
    let mut env = RomEnv::new();

    // Create local references for printing
    let mci = &env.mci;
    mci.set_flow_milestone(McuBootMilestones::ROM_STARTED.into());

    romtime::println!(
        "[mcu-rom] Device lifecycle: {}",
        match mci.device_lifecycle_state() {
            DeviceLifecycle::Value::DeviceUnprovisioned => "Unprovisioned",
            DeviceLifecycle::Value::DeviceManufacturing => "Manufacturing",
            DeviceLifecycle::Value::DeviceProduction => "Production",
        }
    );

    romtime::println!(
        "[mcu-rom] MCI generic input wires[0]: {}",
        HexWord(mci.registers.mci_reg_generic_input_wires[0].get())
    );
    romtime::println!(
        "[mcu-rom] MCI generic input wires[1]: {}",
        HexWord(mci.registers.mci_reg_generic_input_wires[1].get())
    );

    // Read and print the reset reason register
    let reset_reason = mci.registers.mci_reg_reset_reason.get();
    romtime::println!("[mcu-rom] MCI RESET_REASON: 0x{:08x}", reset_reason);

    // Handle different reset reasons
    use romtime::McuResetReason;
    match mci.reset_reason_enum() {
        McuResetReason::ColdBoot => {
            romtime::println!("[mcu-rom] Cold boot detected");
            ColdBoot::run(&mut env, params);
        }
        McuResetReason::WarmReset => {
            romtime::println!("[mcu-rom] Warm reset detected");
            WarmBoot::run(&mut env, params);
        }
        McuResetReason::FirmwareBootReset => {
            romtime::println!("[mcu-rom] Firmware boot reset detected");
            FwBoot::run(&mut env, params);
        }
        McuResetReason::FirmwareHitlessUpdate => {
            romtime::println!("[mcu-rom] Starting firmware hitless update flow");
            FwHitlessUpdate::run(&mut env, params);
        }
        McuResetReason::Invalid => {
            romtime::println!("[mcu-rom] Invalid reset reason: multiple bits set");
            fatal_error(McuError::ROM_ROM_INVALID_RESET_REASON);
        }
    }
}

#[derive(Debug, Default)]
pub struct AxiUsers {
    pub mbox_users: [Option<u32>; 5],
    pub fuse_user: u32,
    pub trng_user: u32,
    pub dma_user: u32,
}

impl From<&RomParameters<'_>> for AxiUsers {
    fn from(params: &RomParameters) -> Self {
        AxiUsers {
            mbox_users: params
                .cptra_mbox_axi_users
                .map(|u| if u != 0 { Some(u) } else { None }),
            fuse_user: params.cptra_fuse_axi_user,
            trng_user: params.cptra_trng_axi_user,
            dma_user: params.cptra_dma_axi_user,
        }
    }
}
