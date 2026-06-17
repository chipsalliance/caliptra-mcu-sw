/*++

Licensed under the Apache-2.0 license.

File Name:

    riscv.rs

Abstract:

    File contains the common RISC-V code for MCU ROM

--*/

#![allow(clippy::empty_loop)]

use crate::fuses::{DefaultVendorKeyPolicy, VendorKeyPolicy};
use crate::hil::FlashStorage;

use crate::fatal_error;
use crate::ColdBoot;
use crate::FwBoot;
use crate::FwHitlessUpdate;
use crate::ImageVerifier;
use crate::RomEnv;
use crate::WarmBoot;
use caliptra_api::mailbox::CmStableKeyType;
#[cfg(all(not(test), feature = "cfi"))]
use caliptra_cfi_derive::{cfi_impl_fn, cfi_mod_fn};
use caliptra_cfi_lib::{cfi_assert_eq, cfi_launder, CfiCounter, CfiError};
use caliptra_drivers::AxiAddr;
use caliptra_mcu_error::McuError;
use caliptra_mcu_registers_generated::fuses;
use caliptra_mcu_registers_generated::mci;
use caliptra_mcu_registers_generated::mci::bits::SecurityState::DeviceLifecycle;
use caliptra_mcu_registers_generated::soc;
use caliptra_mcu_romtime::otp::{Otp, PROD_DEBUG_UNLOCK_PK_ENTRIES};
use caliptra_mcu_romtime::LifecycleControllerState;
use caliptra_mcu_romtime::LifecycleHashedTokens;
use caliptra_mcu_romtime::LifecycleToken;
use caliptra_mcu_romtime::Mci;
use caliptra_mcu_romtime::PqcKeyType;
use caliptra_mcu_romtime::{HexWord, McuBootMilestones, StaticRef};
use core::fmt::Write;
use core::marker::PhantomData;
use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::{Readable, Writeable};

// values when setting in Caliptra
const MLDSA_CALIPTRA_VALUE: u8 = 1;
const LMS_CALIPTRA_VALUE: u8 = 3;
const OTP_DAI_IDLE_BIT_OFFSET: u32 = 30;
const OTP_STATUS_REG_OFFSET: u32 = 0x10;
const OTP_DIRECT_ACCESS_CMD_REG_OFFSET: u32 = 0x80;

pub const MCU_SRAM_DEFAULT_PROTECTED_REGION_BLOCKS: u32 = 8; // 32 kB / 4 kB chunks

/// Trait for different boot flows (cold boot, warm reset, firmware update)
pub trait BootFlow {
    /// Execute the boot flow
    fn run(env: &mut RomEnv, params: RomParameters) -> !;
}

/// An entropy source provided by the integrator, used for initializing the CFI counters.
pub trait CfiEntropySource {
    fn entropy(&mut self) -> Result<(u32, u32, u32, u32), CfiError>;
}

extern "C" {
    pub static MCU_MEMORY_MAP: caliptra_mcu_config::McuMemoryMap;
    pub static MCU_STRAPS: caliptra_mcu_config::McuStraps;
}

pub struct Soc {
    registers: StaticRef<soc::regs::Soc>,
}

#[derive(Default)]
pub struct FuseParams<'a, 'b> {
    #[cfg(feature = "ocp-lock")]
    pub ocp_lock_config: Option<&'b mut caliptra_mcu_romtime::ocp_lock::RomConfig<'a>>,
    /// Policy for selecting the vendor public key slot.
    pub vendor_key_policy: Option<&'a dyn VendorKeyPolicy>,
    /// Number of production debug unlock authentication public key hashes
    /// programmed into the MCI PK hash register bank. When `None`, defaults
    /// to the number of entries in `PROD_DEBUG_UNLOCK_PK_ENTRIES`.
    pub prod_debug_unlock_auth_pk_hash_count: Option<u32>,
    // Used to prevent compiler warnings for unused lifetime.
    pub _inner: PhantomData<(&'a (), &'b ())>,
}

/// Reports the state of Fuses back to the caller
pub struct FuseState {
    #[cfg(feature = "ocp-lock")]
    pub hek_state: Option<caliptra_mcu_romtime::ocp_lock::HekState>,
    pub pk_hash_idx: usize,
}

impl Soc {
    pub const BOOT_FSM_DONE: u32 = 4;
    pub const PK_HASH_SKIP_LOCK_STRAPPING_MASK: u32 = 0x1;
    pub const PK_HASH_ROTATION_STRAPPING_MASK: u32 = 0x1 << 1;

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
        let start = caliptra_mcu_romtime::mcycle();
        while self.boot_fsm_ps() != Self::BOOT_FSM_DONE {
            if self.cptra_fw_fatal_error() {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom] Caliptra reported a fatal error during boot FSM transition"
                );
                fatal_error(McuError::ROM_SOC_CALIPTRA_FATAL_ERROR_BEFORE_FW_READY);
            }
            if caliptra_mcu_romtime::mcycle() - start > timeout_cycles {
                caliptra_mcu_romtime::println!(
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
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Caliptra reported an ICCM ECC uncorrectable error"
            );
            fatal_error(McuError::ROM_SOC_ICCM_ECC_UNC);
        }
        if hw_error.is_set(soc::bits::CptraHwErrorFatal::DccmEccUnc) {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Caliptra reported a DCCM ECC uncorrectable error"
            );
            fatal_error(McuError::ROM_SOC_DCCM_ECC_UNC);
        }
    }

    pub fn set_cptra_wdt_cfg(&self, index: usize, value: u32) {
        if let Some(reg) = self.registers.cptra_wdt_cfg.get(index) {
            reg.set(value);
        } else {
            fatal_error(McuError::ROM_SOC_WDT_CFG_OUT_OF_RANGE);
        }
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
    #[cfg_attr(all(not(test), feature = "cfi"), cfi_impl_fn)]
    pub fn populate_fuses(
        &self,
        otp: &Otp,
        mci: &caliptra_mcu_romtime::Mci,
        params: &mut FuseParams,
    ) -> FuseState {
        // secret fuses are populated by a hardware state machine, so we can skip those

        // UDS partition base address. (FE offset is calculated automatically by Caliptra ROM.)
        // Only set it if it's not already configured.
        let current_uds_addr = AxiAddr {
            lo: self.registers.ss_uds_seed_base_addr_l.get(),
            hi: self.registers.ss_uds_seed_base_addr_h.get(),
        };
        if current_uds_addr == 0u64.into() {
            let offset = fuses::SECRET_MANUF_PARTITION_BYTE_OFFSET;
            caliptra_mcu_romtime::println!(
                "[mcu-fuse-write] Setting UDS/FE base address to {:x}",
                offset
            );
            self.registers.ss_uds_seed_base_addr_l.set(offset as u32);
            self.registers.ss_uds_seed_base_addr_h.set(0);
        }

        caliptra_mcu_romtime::println!(
            "[mcu-fuse-write] Setting UDS/FE DAI idle bit offset to {}, OTP status reg offset to {}, and direct access cmd reg offset to {}",
            OTP_DAI_IDLE_BIT_OFFSET,
            OTP_STATUS_REG_OFFSET,
            OTP_DIRECT_ACCESS_CMD_REG_OFFSET
        );
        self.registers.ss_strap_generic[0]
            .set((OTP_DAI_IDLE_BIT_OFFSET << 16) | OTP_STATUS_REG_OFFSET);
        self.registers.ss_strap_generic[1].set(OTP_DIRECT_ACCESS_CMD_REG_OFFSET);

        // Select the vendor public key slot to use.
        let default_policy = DefaultVendorKeyPolicy::new(
            mci.registers.mci_reg_generic_input_wires[1].get()
                & Self::PK_HASH_ROTATION_STRAPPING_MASK
                != 0,
        );
        let policy = params.vendor_key_policy.unwrap_or(&default_policy);
        let pk_hash_idx = policy
            .select_key(otp)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_PK_HASH_SELECTION_FAILED));
        let pk_hash_idx_expected = cfi_launder(pk_hash_idx);
        caliptra_mcu_romtime::println!("[mcu-fuse-write] Selected vendor PK slot {}", pk_hash_idx);

        #[cfg(feature = "stable-owner-key")]
        crate::stable_owner_key::enable_owner_key_strap(self.registers);

        // PQC Key Type.
        cfi_assert_eq(pk_hash_idx, pk_hash_idx_expected);
        let pqc_type = otp
            .read_pqc_key_type(pk_hash_idx)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        let pqc_caliptra_val = match pqc_type {
            PqcKeyType::MLDSA => MLDSA_CALIPTRA_VALUE,
            PqcKeyType::LMS => LMS_CALIPTRA_VALUE,
        };
        self.registers
            .fuse_pqc_key_type
            .set(pqc_caliptra_val as u32);
        caliptra_mcu_romtime::println!(
            "[mcu-fuse-write] Setting vendor PQC type to {}",
            pqc_caliptra_val
        );

        // FMC Key Manifest SVN.
        let svn = otp
            .read_u32_at(fuses::OTP_CPTRA_CORE_FMC_KEY_MANIFEST_SVN.byte_offset)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        self.registers.fuse_fmc_key_manifest_svn.set(svn);

        // Vendor PK Hash.

        let mut hash_buf = [0u8; 48];
        cfi_assert_eq(pk_hash_idx, pk_hash_idx_expected);
        otp.read_vendor_pk_hash(pk_hash_idx, &mut hash_buf)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        for (reg, word_bytes) in self
            .registers
            .fuse_vendor_pk_hash
            .iter()
            .zip(hash_buf.chunks_exact(4))
        {
            let word = u32::from_le_bytes(
                word_bytes
                    .try_into()
                    .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR)),
            );

            reg.set(word);
        }

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
        cfi_assert_eq(pk_hash_idx, pk_hash_idx_expected);
        let word = otp
            .read_vendor_ecc_revocation(pk_hash_idx)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        self.registers.fuse_ecc_revocation.set(word);

        // LMS Revocation.
        cfi_assert_eq(pk_hash_idx, pk_hash_idx_expected);
        let word = otp
            .read_vendor_lms_revocation(pk_hash_idx)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        self.registers.fuse_lms_revocation.set(word);

        // MLDSA Revocation.
        cfi_assert_eq(pk_hash_idx, pk_hash_idx_expected);
        let word = otp
            .read_vendor_mldsa_revocation(pk_hash_idx)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        self.registers.fuse_mldsa_revocation.set(word);

        // Owner PK hash is sent via mailbox after the DOT flow; see
        // device_ownership_transfer::install_owner_pk_hash().

        // Stable owner key builds forward HEK for derivation here.
        // OCP LOCK keeps its HEK selection and handoff metadata in the OCP path below.
        #[cfg(feature = "stable-owner-key")]
        crate::stable_owner_key::set_hek_fuses(self.registers, otp);

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
                if !mci.write_prod_debug_unlock_pk_hash(reg_idx, word) {
                    fatal_error(McuError::ROM_SOC_PROD_DEBUG_UNLOCK_PKS_HASH_LEN_MISMATCH);
                }
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

        // Tell Caliptra where to find the prod debug unlock PK hashes and how
        // many are valid. The offset is the address of
        // `mci_reg_prod_debug_unlock_pk_hash_reg` within the MCI register
        // bank; Caliptra reads `MCI_BASE + offset + (level - 1) * 48` during
        // prod debug unlock authentication.
        let num_pk_hashes = params
            .prod_debug_unlock_auth_pk_hash_count
            .unwrap_or(PROD_DEBUG_UNLOCK_PK_ENTRIES.len() as u32);
        caliptra_mcu_romtime::println!(
            "[mcu-fuse-write] Setting prod debug unlock PK hash bank offset to {:x}, count {}",
            caliptra_mcu_romtime::MCI_PROD_DEBUG_UNLOCK_PK_HASH_REG_BANK_OFFSET,
            num_pk_hashes
        );
        self.registers
            .ss_prod_debug_unlock_auth_pk_hash_reg_bank_offset
            .set(caliptra_mcu_romtime::MCI_PROD_DEBUG_UNLOCK_PK_HASH_REG_BANK_OFFSET);
        self.registers
            .ss_num_of_prod_debug_unlock_auth_pk_hashes
            .set(num_pk_hashes);

        // We use non secret production fuses to have caliptra tests pass some initial fuse values
        if cfg!(feature = "core_test") {
            // UDS Seed from fuses (split into low and high 256-bit halves)

            let uds_seed_lo_offset = fuses::FPGA_TEST_UDS_SEED_LO.byte_offset;
            let uds_seed_hi_offset = fuses::FPGA_TEST_UDS_SEED_HI.byte_offset;
            for i in 0..8 {
                let word = otp
                    .read_u32_at(uds_seed_lo_offset + i * 4)
                    .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
                self.registers.fuse_uds_seed[i].set(word);
            }
            for i in 0..8 {
                let word = otp
                    .read_u32_at(uds_seed_hi_offset + i * 4)
                    .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
                self.registers.fuse_uds_seed[8 + i].set(word);
            }

            // Field Entropy from fuses

            let field_entropy_offset = fuses::FPGA_TEST_FIELD_ENTROPY.byte_offset;
            for i in 0..self.registers.fuse_field_entropy.len() {
                let word = otp
                    .read_u32_at(field_entropy_offset + i * 4)
                    .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
                self.registers.fuse_field_entropy[i].set(word);
            }
        }

        caliptra_mcu_romtime::println!("");

        #[cfg(feature = "ocp-lock")]
        let hek_state = if let Some(ref mut config) = params.ocp_lock_config {
            caliptra_mcu_romtime::println!("[mcu-rom] OCP LOCK enabled");
            // TODO(clundin): Need to communicate HEK availability to firmware.
            match self.set_ocp_lock_fuses(otp, config) {
                Ok(state) => Some(state),
                Err(caliptra_mcu_romtime::ocp_lock::Error::ROM_EXHAUSTED_HEK_SLOTS) => None,
                Err(_) => fatal_error(McuError::ROM_OTP_OCP_LOCK_FAILURE),
            }
        } else {
            fatal_error(McuError::OCP_LOCK_ROM_MISSING_CONFIG)
        };

        FuseState {
            #[cfg(feature = "ocp-lock")]
            hek_state,
            pk_hash_idx,
        }
    }

    /// OCP LOCK Fuses.
    #[cfg(feature = "ocp-lock")]
    pub fn set_ocp_lock_fuses(
        &self,
        otp: &Otp,
        config: &mut caliptra_mcu_romtime::ocp_lock::RomConfig,
    ) -> Result<caliptra_mcu_romtime::ocp_lock::HekState, caliptra_mcu_romtime::ocp_lock::Error>
    {
        // Key release is always 64 bytes currently
        self.registers.ss_key_release_size.set(config.mek_size);

        self.registers
            .ss_key_release_base_addr_h
            .set((config.key_release_addr >> 32) as u32);
        self.registers
            .ss_key_release_base_addr_l
            .set(config.key_release_addr as u32);

        let perma_status = if config
            .is_perma_bit_set(otp)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR))
        {
            caliptra_mcu_romtime::ocp_lock::PermaBitStatus::Set
        } else {
            caliptra_mcu_romtime::ocp_lock::PermaBitStatus::Unset
        };

        let mut seeds = [[0u8; 48]; 8];
        for (i, seed) in seeds.iter_mut().enumerate() {
            otp.read_hek_seed(i, seed)
                .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));
        }

        let total_slots = seeds.len();

        let hek_seeds = caliptra_mcu_romtime::ocp_lock::HekSeeds::new(&seeds[..]);
        let active_slot = match config.get_active_slot(otp, &perma_status, &hek_seeds) {
            Ok(slot) => slot,
            Err(caliptra_mcu_romtime::ocp_lock::Error::ROM_EXHAUSTED_HEK_SLOTS) => {
                return Err(caliptra_mcu_romtime::ocp_lock::Error::ROM_EXHAUSTED_HEK_SLOTS)
            }
            Err(_) => fatal_error(McuError::ROM_OTP_READ_ERROR),
        };

        let platform = config
            .platform
            .as_mut()
            .ok_or(caliptra_mcu_romtime::ocp_lock::Error::ROM_MISSING_PLATFORM_IMPLEMENTATION)?;

        let (active_slot, active_state, seed_buf) = {
            let buf = hek_seeds
                .get(active_slot)
                .ok_or(caliptra_mcu_romtime::ocp_lock::Error::ROM_INVALID_HEK_SLOT)?;
            let state = platform.get_slot_state(otp, &perma_status, active_slot, buf)?;
            (active_slot, state, buf)
        };

        match active_state {
            caliptra_mcu_romtime::ocp_lock::HekSeedState::Permanent
            | caliptra_mcu_romtime::ocp_lock::HekSeedState::Sanitized => {
                for word in self.registers.fuse_hek_seed.iter() {
                    word.set(0xFFFF_FFFF);
                }
            }
            caliptra_mcu_romtime::ocp_lock::HekSeedState::ProgrammedCorrupted
            | caliptra_mcu_romtime::ocp_lock::HekSeedState::SanitizedPendingReset
            | caliptra_mcu_romtime::ocp_lock::HekSeedState::ProgrammedPendingReset
            | caliptra_mcu_romtime::ocp_lock::HekSeedState::SanitizedCorrupted
            | caliptra_mcu_romtime::ocp_lock::HekSeedState::Unused => {
                for word in self.registers.fuse_hek_seed.iter() {
                    word.set(0);
                }
            }
            caliptra_mcu_romtime::ocp_lock::HekSeedState::Programmed => {
                for (reg, word) in
                    self.registers.fuse_hek_seed.iter().zip(
                        seed_buf.chunks_exact(core::mem::size_of::<u32>()).map(|w| {
                            u32::from_le_bytes(w.try_into().unwrap_or_else(|_| {
                                fatal_error(McuError::ROM_OTP_WRITE_WORD_ERROR)
                            }))
                        }),
                    )
                {
                    reg.set(word);
                }
            }
        };

        Ok(caliptra_mcu_romtime::ocp_lock::HekState {
            active_slot: active_slot as u32,
            reserved: 0,
            total_slots: total_slots as u32,
            active_state,
        })
    }

    pub fn pk_hash_volatile_lock(&self, otp: &Otp, mci: &Mci, selected_index: usize) {
        // Read generic input wires to check for provisioning mode.
        let input_wires = mci.registers.mci_reg_generic_input_wires[1].get();
        if (input_wires & Self::PK_HASH_SKIP_LOCK_STRAPPING_MASK) != 0 {
            caliptra_mcu_romtime::println!(
              "[mcu-fuse-write] PK Hash provisioning mode detected, skipping vendor PK hash lock."
          );
        } else {
            caliptra_mcu_romtime::println!(
                "[mcu-fuse-write] Locking vendor PK hash slots from index {}",
                selected_index
            );
            otp.volatile_lock(selected_index as u32);
        }
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
                caliptra_mcu_romtime::println!(
                    "[mcu-rom] Setting Caliptra mailbox user {i} to {}",
                    HexWord(user)
                );
                self.set_cptra_mbox_valid_axi_user(i, user);
                caliptra_mcu_romtime::println!("[mcu-rom] Locking Caliptra mailbox user {i}");
                self.set_cptra_mbox_axi_user_lock(i, 1);
            }
        }

        if fuse_user != 0 {
            caliptra_mcu_romtime::println!("[mcu-rom] Setting fuse user");
            self.set_cptra_fuse_valid_axi_user(fuse_user);
            caliptra_mcu_romtime::println!("[mcu-rom] Locking fuse user");
            self.set_cptra_fuse_axi_user_lock(1);
        }
        if trng_user != 0 {
            caliptra_mcu_romtime::println!("[mcu-rom] Setting TRNG user");
            self.set_cptra_trng_valid_axi_user(trng_user);
            caliptra_mcu_romtime::println!("[mcu-rom] Locking TRNG user");
            self.set_cptra_trng_axi_user_lock(1);
        }
        if dma_user != 0 {
            caliptra_mcu_romtime::println!("[mcu-rom] Setting DMA user");
            self.set_ss_caliptra_dma_axi_user(dma_user);
        }
    }

    #[cfg_attr(all(not(test), feature = "cfi"), cfi_impl_fn)]
    pub fn fuse_write_done(&self) {
        self.registers.cptra_fuse_wr_done.set(1);
    }

    /// Waits for Caliptra to indicate MCU firmware is ready through the `NotifCptraMcuResetReqSts`
    /// interrupt.
    pub fn wait_for_firmware_ready(&self, mci: &caliptra_mcu_romtime::Mci) {
        let notif0 = &mci.registers.intr_block_rf_notif0_internal_intr_r;
        // TODO(zhalvorsen): use interrupt instead of fw_exec_ctrl register when the emulator supports it
        // Wait for a reset request from Caliptra
        while !self.fw_ready() {
            if self.cptra_fw_fatal_error() {
                caliptra_mcu_romtime::println!("[mcu-rom] Caliptra reported a fatal error");
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
    mci: &caliptra_mcu_romtime::Mci,
    mbox0_axi_users: &[u32; 5],
    mbox1_axi_users: &[u32; 5],
) -> McuMboxAxiUserConfig {
    let mut config = McuMboxAxiUserConfig::default();

    // Configure MBOX0 AXI users
    for (i, user) in mbox0_axi_users.iter().enumerate() {
        // skip unconfigured users and avoid impossible panics
        if *user != 0 && i < config.mbox0_users.len() && i < config.mbox0_locks.len() {
            caliptra_mcu_romtime::println!(
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
            caliptra_mcu_romtime::println!(
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
pub fn verify_prod_debug_unlock_pk_hash(
    mci: &caliptra_mcu_romtime::Mci,
    otp: &Otp,
) -> Result<(), McuError> {
    // Verify length matches: 384 bytes = 96 u32 words
    let pk_hash_len = mci.prod_debug_unlock_pk_hash_len();
    if pk_hash_len != 96 {
        return Err(McuError::ROM_SOC_PK_HASH_VERIFY_LEN_MISMATCH);
    }

    // Compare word-by-word to minimize stack usage
    // Each of the 8 hashes is 48 bytes (12 words)
    let mut mismatch = false;
    for hash_idx in 0..8 {
        let entry = PROD_DEBUG_UNLOCK_PK_ENTRIES
            .get(hash_idx)
            .ok_or(McuError::ROM_SOC_PK_HASH_VERIFY_INTERNAL_ERROR)?;
        let hash_base_offset = entry.byte_offset;
        for word_idx in 0..12 {
            let reg_idx = hash_idx * 12 + word_idx;
            let expected = otp
                .read_u32_at(hash_base_offset + word_idx * 4)
                .map_err(|_| McuError::ROM_SOC_PK_HASH_VERIFY_OTP_READ_FAILED)?;
            let actual = mci.read_prod_debug_unlock_pk_hash(reg_idx).unwrap_or(0);
            // Use bitwise OR to accumulate mismatches (constant-time)
            mismatch |= expected != actual;
        }
    }

    if mismatch {
        return Err(McuError::ROM_SOC_PK_HASH_VERIFY_MISMATCH);
    }
    caliptra_mcu_romtime::println!("[mcu-rom] Prod debug unlock PK hash verification passed");
    Ok(())
}

/// Verifies that the MCU mailbox AXI user configuration hasn't been tampered with
/// after SS_CONFIG_DONE_STICKY is set.
#[cfg_attr(all(not(test), feature = "cfi"), cfi_mod_fn)]
pub fn verify_mcu_mbox_axi_users(
    mci: &caliptra_mcu_romtime::Mci,
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
                return Err(McuError::ROM_SOC_MCU_MBOX0_AXI_USER_VERIFY_FAILED);
            }
        }
        // Verify lock status matches expected
        let actual_locked = mci.read_mbox0_axi_user_lock(i).unwrap_or(false);
        if *expected_lock != actual_locked {
            return Err(McuError::ROM_SOC_MCU_MBOX0_AXI_USER_LOCK_VERIFY_FAILED);
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
                return Err(McuError::ROM_SOC_MCU_MBOX1_AXI_USER_VERIFY_FAILED);
            }
        }
        // Verify lock status matches expected
        let actual_locked = mci.read_mbox1_axi_user_lock(i).unwrap_or(false);
        if *expected_lock != actual_locked {
            return Err(McuError::ROM_SOC_MCU_MBOX1_AXI_USER_LOCK_VERIFY_FAILED);
        }
    }

    caliptra_mcu_romtime::println!("[mcu-rom] MCU mailbox AXI user verification passed");
    Ok(())
}

bitflags::bitflags! {
    /// Bitmask of I3C service modes the ROM may enter when appropriate.
    ///
    /// Each flag enables a category of I3C mailbox commands that the ROM will
    /// accept. The ROM enters I3C services mode either when a relevant
    /// condition is met (e.g., DOT recovery needed) or unconditionally when
    /// `force_i3c_services` is set on `RomParameters`.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct I3cServicesModes: u32 {
        /// Enable DOT recovery commands over I3C.
        const DOT_RECOVERY = 1 << 0;
    }
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
    pub image_provider_manager: Option<crate::recovery::ImageProviderManager<'a>>,
    /// Whether or not to program field entropy after booting Caliptra runtime firmware
    pub program_field_entropy: [bool; 4],
    pub mcu_image_header_size: usize,
    pub mcu_image_verifier: Option<&'a dyn ImageVerifier>,
    /// The stable key type to use for DOT operations (IDevID or LDevID; IDevID is the default if not specified).
    pub dot_stable_key_type: Option<CmStableKeyType>,
    /// Flash storage interface for DOT blob.
    pub dot_flash: Option<&'a dyn FlashStorage>,
    /// Selects whether the owner PK hash comes from the DOT flow (with fuse
    /// fallback) or is forced to the `CPTRA_SS_OWNER_PK_HASH` fuse, bypassing
    /// the DOT blob. Default: [`OwnerPkHashPolicy::DotThenFuse`].
    pub owner_pk_hash_policy: crate::device_ownership_transfer::OwnerPkHashPolicy,
    /// Whether to check for and process firmware manifest DOT commands.
    /// When true, the ROM will look for a FwManifestDotSection at the start
    /// of MCU SRAM during FwBoot and process any DOT commands found.
    /// Default: false (opt-in by platform integrators).
    pub fw_manifest_dot_enabled: bool,
    /// Recovery handler for recovering from corrupted DOT blob in ODD state (backup blob flow).
    pub dot_recovery_handler: Option<&'a dyn crate::DotRecoveryHandler>,
    /// Whether to attempt backup-blob recovery.
    pub dot_recovery_policy: DotRecoveryPolicy,
    /// Whether to check for and process the MCU Component SVN Manifest header.
    /// When true, ROM looks for the manifest magic after the static
    /// `mcu_image_header_size` plus any DOT section, validates it, and
    /// advances the firmware entry offset past it. See `docs/src/svn.md`.
    /// Default: false (opt-in by platform integrators).
    pub svn_manifest_enabled: bool,
    /// Platform mapping from SoC `component_id` to a `SOC_IMAGE_MIN_SVN[i]`
    /// fuse slot, used to burn per-component SVN floors from the MCU
    /// Component SVN Manifest entries. Empty (the default) disables
    /// per-component burns. See `docs/src/svn.md`.
    pub svn_fuse_map: &'a [crate::SvnFuseMapEntry],
    /// Recovery/override transport for DOT challenge/response protocol (e.g., MCI mbox0, I3C).
    pub dot_recovery_transport: Option<&'a dyn crate::RecoveryTransport>,
    /// DOT recovery/override watchdog timeout in clock cycles. If non-zero,
    /// the MCU watchdog is configured with this value before waiting for
    /// mbox0 commands during recovery or override. 0 = no watchdog.
    pub dot_recovery_wdt_timeout: u64,
    /// Integrator-ordered list of DOT locked-state recovery handlers.
    /// When DOT is in ODD state, the ROM iterates through these in order,
    /// respecting each entry's error policy. The first handler that succeeds
    /// triggers a warm reset. If empty, no locked-state recovery is attempted.
    pub dot_locked_recovery_handlers:
        &'a [crate::device_ownership_transfer::DotLockedRecoveryEntry<'a>],
    pub otp_enable_integrity_check: bool,
    pub otp_enable_consistency_check: bool,
    pub otp_check_timeout_override: Option<u32>,
    /// Request recovery boot (AXI recovery bypass).
    pub request_recovery_boot: bool,
    /// By default, we will set recovery status as successful after loading MCU firmware.
    /// Set this to true if you want to leave recovery status as open for further firmware image loading.
    /// Note that in 2.0, Caliptra already sets recovery status as successful so there may be a race
    /// condition depending on when a BMC reads the recovery status.
    pub recovery_status_open: bool,
    /// Size of the executable SRAM region to pass into FW_SRAM_EXEC_REGION_SIZE
    pub mcu_fw_sram_exec_region_size: Option<u32>,
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
    pub stash_rom_digest: Option<bool>,
    #[cfg(feature = "ocp-lock")]
    pub ocp_lock_config: caliptra_mcu_romtime::ocp_lock::RomConfig<'a>,
    /// Policy for selecting the vendor public key slot.
    pub vendor_key_policy: Option<&'a dyn VendorKeyPolicy>,
    /// OTP digest IV and finalization constant (platform-specific RTL constants).
    /// Required to use `Otp::compute_sw_digest` and `Otp::write_sw_digest_and_lock`.
    pub otp_digest_iv: Option<u64>,
    pub otp_digest_const: Option<u128>,
    /// Caliptra entropy bypass mode. See [spec](https://chipsalliance.github.io/caliptra-web/docs/2.1/firmware/rom_spec.html#entropy-source-configuration-registers)
    /// for more details.
    pub itrng_entropy_bypass_mode: bool,
    /// Optional bitmask of I3C service modes the ROM may enter.
    /// When `None`, no I3C services are available. When set, the ROM will
    /// enter the I3C mailbox handler for the enabled services when the
    /// appropriate condition is met (e.g., DOT recovery needed).
    pub i3c_services: Option<I3cServicesModes>,
    /// When true, the ROM unconditionally enters the I3C services handler
    /// at the appropriate point in the boot flow, regardless of whether a
    /// triggering condition (like DOT failure) occurred.
    pub force_i3c_services: bool,
    /// Optional callbacks invoked at major ROM milestones. See
    /// [`RomHooks`](crate::RomHooks) for the full list of hook points.
    pub hooks: Option<&'a dyn crate::RomHooks>,
    /// Number of production debug unlock authentication public key hashes
    /// programmed into the MCI PK hash register bank. The ROM writes this
    /// value to `SS_NUM_OF_PROD_DEBUG_UNLOCK_AUTH_PK_HASHES` so Caliptra knows
    /// how many hashes are available for prod debug unlock. When `None`, the
    /// ROM uses the reference fuse map count (number of entries in
    /// `PROD_DEBUG_UNLOCK_PK_ENTRIES`).
    pub prod_debug_unlock_auth_pk_hash_count: Option<u32>,
    /// An optional entropy source used for the initialization of CFI counters before Caliptra
    /// mailbox is available. If `None` and CFI is enabled, initialization will error out.
    pub cfi_entropy_source: Option<&'a mut dyn CfiEntropySource>,
    /// Optional I3C bus timing parameters for the primary controller (i3c),
    /// written to its timing registers during I3C initialization. When `None`,
    /// [`I3cTimings::default`] is used (recommended settings for high-speed
    /// parts).
    pub i3c_timings: Option<crate::I3cTimings>,
    /// Optional I3C bus timing parameters for the secondary controller (i3c1),
    /// used when it is the active controller. When `None`,
    /// [`I3cTimings::default`] is used.
    pub i3c1_timings: Option<crate::I3cTimings>,
}

fn initialize_cfi_state(params: &mut RomParameters) {
    match &mut params.cfi_entropy_source {
        None => {
            if cfg!(feature = "cfi") {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom] CFI enabled but no early entropy source available"
                );
                fatal_error(McuError::ROM_CFI_NO_EARLY_ENTROPY_SOURCE);
            }
        }
        Some(source) => {
            let mut entropy_gen = || source.entropy();
            CfiCounter::reset(&mut entropy_gen);
            CfiCounter::reset(&mut entropy_gen);
            CfiCounter::reset(&mut entropy_gen);
        }
    }
}

pub fn rom_start(mut params: RomParameters) {
    caliptra_mcu_romtime::println!("[mcu-rom] Hello from ROM");
    #[cfg(feature = "ocp-lock")]
    caliptra_mcu_romtime::println!("[mcu-rom] OCP LOCK feature enabled");

    initialize_cfi_state(&mut params);

    // Create ROM environment with all peripherals
    let mut env = RomEnv::new();

    // Create local references for printing
    let mci = &env.mci;
    mci.set_flow_milestone(McuBootMilestones::ROM_STARTED.into());

    caliptra_mcu_romtime::println!(
        "[mcu-rom] Device lifecycle: {}",
        match mci.device_lifecycle_state() {
            DeviceLifecycle::Value::DeviceUnprovisioned => "Unprovisioned",
            DeviceLifecycle::Value::DeviceManufacturing => "Manufacturing",
            DeviceLifecycle::Value::DeviceProduction => "Production",
        }
    );

    caliptra_mcu_romtime::println!(
        "[mcu-rom] MCI generic input wires[0]: {}",
        HexWord(mci.registers.mci_reg_generic_input_wires[0].get())
    );
    caliptra_mcu_romtime::println!(
        "[mcu-rom] MCI generic input wires[1]: {}",
        HexWord(mci.registers.mci_reg_generic_input_wires[1].get())
    );

    // Read and print the reset reason register
    let reset_reason = mci.registers.mci_reg_reset_reason.get();
    caliptra_mcu_romtime::println!("[mcu-rom] MCI RESET_REASON: 0x{:08x}", reset_reason);

    // Handle different reset reasons
    use caliptra_mcu_romtime::McuResetReason;
    match mci.reset_reason_enum() {
        McuResetReason::ColdBoot => {
            caliptra_mcu_romtime::println!("[mcu-rom] Cold boot detected");
            ColdBoot::run(&mut env, params);
        }
        McuResetReason::WarmReset => {
            caliptra_mcu_romtime::println!("[mcu-rom] Warm reset detected");
            WarmBoot::run(&mut env, params);
        }
        McuResetReason::FirmwareBootReset => {
            caliptra_mcu_romtime::println!("[mcu-rom] Firmware boot reset detected");
            FwBoot::run(&mut env, params);
        }
        McuResetReason::FirmwareHitlessUpdate => {
            caliptra_mcu_romtime::println!("[mcu-rom] Starting firmware hitless update flow");
            FwHitlessUpdate::run(&mut env, params);
        }
        McuResetReason::Invalid => {
            caliptra_mcu_romtime::println!("[mcu-rom] Invalid reset reason: multiple bits set");
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
