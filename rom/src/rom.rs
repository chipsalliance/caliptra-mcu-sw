/*++

Licensed under the Apache-2.0 license.

File Name:

    riscv.rs

Abstract:

    File contains the common RISC-V code for MCU ROM

--*/

#![allow(clippy::empty_loop)]

use crate::fatal_error;
use crate::flash::flash_partition::FlashPartition;
use crate::ColdBoot;
use crate::FwBoot;
use crate::FwHitlessUpdate;
use crate::ImageVerifier;
use crate::LifecycleControllerState;
use crate::LifecycleHashedTokens;
use crate::LifecycleToken;
use crate::McuBootMilestones;
use crate::RomEnv;
use crate::WarmBoot;
use core::fmt::Write;
use mcu_error::McuError;
use registers_generated::fuses::Fuses;
use registers_generated::mci;
use registers_generated::mci::bits::SecurityState::DeviceLifecycle;
use registers_generated::soc;
use romtime::{HexWord, StaticRef};
use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::{Readable, Writeable};

// values in fuses
const LMS_FUSE_VALUE: u8 = 1;
const MLDSA_FUSE_VALUE: u8 = 0;
// values when setting in Caliptra
const MLDSA_CALIPTRA_VALUE: u8 = 1;
const LMS_CALIPTRA_VALUE: u8 = 3;

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

    pub fn set_cptra_wdt_cfg(&self, index: usize, value: u32) {
        self.registers.cptra_wdt_cfg[index].set(value);
    }

    pub fn set_cptra_mbox_valid_axi_user(&self, index: usize, value: u32) {
        self.registers.cptra_mbox_valid_axi_user[index].set(value);
    }

    pub fn set_cptra_mbox_axi_user_lock(&self, index: usize, value: u32) {
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

    pub fn populate_fuses(&self, fuses: &Fuses, mci: &romtime::Mci, field_entropy: bool) {
        // secret fuses are populated by a hardware state machine, so we can skip those

        // Field Entropy.
        let offset = if field_entropy {
            registers_generated::fuses::SECRET_PROD_PARTITION_0_BYTE_OFFSET
        } else {
            registers_generated::fuses::SECRET_MANUF_PARTITION_BYTE_OFFSET
        };
        romtime::println!(
            "[mcu-fuse-write] Setting UDS/FE base address to {:x}",
            offset
        );
        self.registers.ss_uds_seed_base_addr_l.set(offset as u32);
        self.registers.ss_uds_seed_base_addr_h.set(0);

        // PQC Key Type.
        let pqc_type = match fuses.cptra_core_pqc_key_type_0()[0] & 1 {
            MLDSA_FUSE_VALUE => MLDSA_CALIPTRA_VALUE,
            LMS_FUSE_VALUE => LMS_CALIPTRA_VALUE,
            _ => unreachable!(),
        };
        self.registers.fuse_pqc_key_type.set(pqc_type as u32);
        romtime::println!("[mcu-fuse-write] Setting vendor PQC type to {}", pqc_type);

        // FMC Key Manifest SVN.
        if size_of_val(fuses.cptra_core_fmc_key_manifest_svn())
            != size_of_val(&self.registers.fuse_fmc_key_manifest_svn)
        {
            fatal_error(McuError::ROM_SOC_KEY_MANIFEST_PK_HASH_LEN_MISMATCH);
        }
        self.registers
            .fuse_fmc_key_manifest_svn
            .set(u32::from_le_bytes(
                fuses
                    .cptra_core_fmc_key_manifest_svn()
                    .try_into()
                    .unwrap_or_else(|_| {
                        fatal_error(McuError::SOC_FMC_KEY_MANIFEST_SVN_LEN_MISMATCH)
                    }),
            ));

        // Vendor PK Hash.
        romtime::print!("[mcu-fuse-write] Writing fuse key vendor PK hash: ");
        if size_of_val(fuses.cptra_core_vendor_pk_hash_0())
            != size_of_val(&self.registers.fuse_vendor_pk_hash)
        {
            fatal_error(McuError::ROM_SOC_KEY_MANIFEST_PK_HASH_LEN_MISMATCH);
        }
        for i in 0..fuses.cptra_core_vendor_pk_hash_0().len() / 4 {
            let word = u32::from_le_bytes(
                fuses.cptra_core_vendor_pk_hash_0()[i * 4..i * 4 + 4]
                    .try_into()
                    .unwrap_or_else(|_| {
                        fatal_error(McuError::ROM_SOC_KEY_MANIFEST_PK_HASH_LEN_MISMATCH)
                    }),
            );
            romtime::print!("{}", HexWord(word));
            self.registers.fuse_vendor_pk_hash[i].set(word);
        }
        romtime::println!("");

        // TODO(clundin): Pass OCP LOCK fuses as a parameter.
        romtime::println!("[mcu-fuse-write] Attempting to write OCP LOCK fuses");

        for i in 0..8 {
            self.registers.fuse_hek_seed[i].set(0xABDE);
        }

        romtime::println!("[mcu-fuse-write] Writing key release fuses");
        self.registers.ss_key_release_size.set(0x40);

        let mci_base_addr: u64 = self.registers.ss_mci_base_addr_l.get() as u64
            + ((self.registers.ss_mci_base_addr_h.get() as u64) << 32);
        let mcu_sram_addr: u64 = 0xc0_0000 + mci_base_addr;
        self.registers
            .ss_key_release_base_addr_h
            .set((mcu_sram_addr >> 32) as u32);
        self.registers
            .ss_key_release_base_addr_l
            .set(mcu_sram_addr as u32);

        romtime::println!("[mcu-fuse-write] Finished writing OCP LOCK fuses");
        romtime::println!("");

        // Runtime SVN.
        if size_of_val(fuses.cptra_core_runtime_svn())
            != size_of_val(&self.registers.fuse_runtime_svn)
        {
            fatal_error(McuError::ROM_SOC_RT_SVN_LEN_MISMATCH);
        }
        for i in 0..fuses.cptra_core_runtime_svn().len() / 4 {
            let word = u32::from_le_bytes(
                fuses.cptra_core_runtime_svn()[i * 4..i * 4 + 4]
                    .try_into()
                    .unwrap_or_else(|_| fatal_error(McuError::ROM_SOC_RT_SVN_LEN_MISMATCH)),
            );
            self.registers.fuse_runtime_svn[i].set(word);
        }

        // SoC Manifest SVN.
        if size_of_val(fuses.cptra_core_soc_manifest_svn())
            != size_of_val(&self.registers.fuse_soc_manifest_svn)
        {
            fatal_error(McuError::ROM_SOC_MANIFEST_SVN_LEN_MISMATCH);
        }
        for i in 0..fuses.cptra_core_soc_manifest_svn().len() / 4 {
            let word = u32::from_le_bytes(
                fuses.cptra_core_soc_manifest_svn()[i * 4..i * 4 + 4]
                    .try_into()
                    .unwrap_or_else(|_| fatal_error(McuError::ROM_SOC_MANIFEST_SVN_LEN_MISMATCH)),
            );
            self.registers.fuse_soc_manifest_svn[i].set(word);
        }

        // SoC Manifest Max SVN.
        if size_of_val(fuses.cptra_core_soc_manifest_max_svn())
            != size_of_val(&self.registers.fuse_soc_manifest_max_svn)
        {
            fatal_error(McuError::SOC_MANIFEST_MAX_SVN_LEN_MISMATCH);
        }
        let word = u32::from_le_bytes(
            fuses
                .cptra_core_soc_manifest_max_svn()
                .try_into()
                .unwrap_or_else(|_| fatal_error(McuError::SOC_MANIFEST_MAX_SVN_LEN_MISMATCH)),
        );
        self.registers.fuse_soc_manifest_max_svn.set(word);

        // Manuf Debug Unlock Token
        if size_of_val(fuses.cptra_ss_manuf_debug_unlock_token())
            != size_of_val(&self.registers.fuse_manuf_dbg_unlock_token)
        {
            fatal_error(McuError::ROM_SOC_MANUF_DEBUG_UNLOCK_TOKEN_LEN_MISMATCH);
        }
        for i in 0..fuses.cptra_ss_manuf_debug_unlock_token().len() / 4 {
            let word = u32::from_le_bytes(
                fuses.cptra_ss_manuf_debug_unlock_token()[i * 4..i * 4 + 4]
                    .try_into()
                    .unwrap_or_else(|_| {
                        fatal_error(McuError::ROM_SOC_MANUF_DEBUG_UNLOCK_TOKEN_LEN_MISMATCH)
                    }),
            );
            self.registers.fuse_manuf_dbg_unlock_token[i].set(word);
        }

        // TODO: vendor-specific fuses when those are supported
        // TODO: load ECC Revocation CSRs.
        // TODO: load LMS Revocation CSRs.
        // TODO: load MLDSA Revocation CSRs.
        // TODO: load HEK Seed CSRs.

        // SoC Stepping ID (only 16-bits are relevant).
        if size_of_val(fuses.cptra_core_soc_stepping_id())
            != size_of_val(&self.registers.fuse_soc_stepping_id)
        {
            fatal_error(McuError::ROM_SOC_STEPPING_ID_LEN_MISMATCH);
        }
        let soc_stepping_id = u16::from_le_bytes(
            fuses.cptra_core_soc_stepping_id()[0..2]
                .try_into()
                .unwrap_or_else(|_| fatal_error(McuError::ROM_SOC_STEPPING_ID_LEN_MISMATCH)),
        ) as u32;
        self.registers
            .fuse_soc_stepping_id
            .write(soc::bits::FuseSocSteppingId::SocSteppingId.val(soc_stepping_id));

        // Anti Rollback Disable.
        if size_of_val(fuses.cptra_core_anti_rollback_disable())
            != size_of_val(&self.registers.fuse_anti_rollback_disable)
        {
            fatal_error(McuError::ROM_SOC_ANTI_ROLLBACK_DISABLE_LEN_MISMATCH);
        }
        let anti_rollback_disable = u32::from_le_bytes(
            fuses
                .cptra_core_anti_rollback_disable()
                .try_into()
                .unwrap_or_else(|_| {
                    fatal_error(McuError::ROM_SOC_ANTI_ROLLBACK_DISABLE_LEN_MISMATCH)
                }),
        );
        self.registers
            .fuse_anti_rollback_disable
            .write(soc::bits::FuseAntiRollbackDisable::Dis.val(anti_rollback_disable));

        // IDevID Cert Attr.
        if size_of_val(fuses.cptra_core_idevid_cert_idevid_attr())
            != size_of_val(&self.registers.fuse_idevid_cert_attr)
        {
            fatal_error(McuError::ROM_SOC_IDEVID_CERT_ATTR_LEN_MISMATCH);
        }
        for i in 0..self.registers.fuse_idevid_cert_attr.len() {
            let word = u32::from_le_bytes(
                fuses.cptra_core_idevid_cert_idevid_attr()[i * 4..i * 4 + 4]
                    .try_into()
                    .unwrap_or_else(|_| {
                        fatal_error(McuError::ROM_SOC_IDEVID_CERT_ATTR_LEN_MISMATCH)
                    }),
            );
            self.registers.fuse_idevid_cert_attr[i].set(word);
        }

        // IDevID Manuf HSM ID.
        if size_of_val(fuses.cptra_core_idevid_manuf_hsm_identifier())
            != size_of_val(&self.registers.fuse_idevid_manuf_hsm_id)
        {
            fatal_error(McuError::ROM_SOC_IDEVID_MANUF_HSM_ID_LEN_MISMATCH);
        }
        for i in 0..self.registers.fuse_idevid_manuf_hsm_id.len() {
            let word = u32::from_le_bytes(
                fuses.cptra_core_idevid_manuf_hsm_identifier()[i * 4..i * 4 + 4]
                    .try_into()
                    .unwrap_or_else(|_| {
                        fatal_error(McuError::ROM_SOC_IDEVID_MANUF_HSM_ID_LEN_MISMATCH)
                    }),
            );
            self.registers.fuse_idevid_manuf_hsm_id[i].set(word);
        }

        // Prod Debug Unlock Public Key Hashes.
        // Copy all 8 prod debug unlock public key hashes into a single buffer.
        let mut prod_dbg_unlock_pks_hashes = [0u8; 384];
        let fuse_slices = [
            &fuses.cptra_ss_prod_debug_unlock_pks_0(),
            &fuses.cptra_ss_prod_debug_unlock_pks_1(),
            &fuses.cptra_ss_prod_debug_unlock_pks_2(),
            &fuses.cptra_ss_prod_debug_unlock_pks_3(),
            &fuses.cptra_ss_prod_debug_unlock_pks_4(),
            &fuses.cptra_ss_prod_debug_unlock_pks_5(),
            &fuses.cptra_ss_prod_debug_unlock_pks_6(),
            &fuses.cptra_ss_prod_debug_unlock_pks_7(),
        ];
        for (i, fuse_slice) in fuse_slices.iter().enumerate() {
            let start = i * 48;
            let end = start + 48;
            if let Some(slice) = prod_dbg_unlock_pks_hashes.get_mut(start..end) {
                if slice.len() != fuse_slice.len() {
                    fatal_error(McuError::ROM_SOC_PROD_DEBUG_UNLOCK_PKS_HASH_LEN_MISMATCH);
                }
                slice.copy_from_slice(fuse_slice);
            } else {
                // This is unreachable as prod_dbg_unlock_pks_hashes is 384 bytes.
                fatal_error(McuError::ROM_SOC_PROD_DEBUG_UNLOCK_PKS_HASH_LEN_MISMATCH);
            }
        }
        // Copy the single public key hashes buffer to the MCI CSRs.
        if size_of_val(&prod_dbg_unlock_pks_hashes)
            != size_of_val(&mci.registers.mci_reg_prod_debug_unlock_pk_hash_reg)
        {
            fatal_error(McuError::ROM_SOC_PROD_DEBUG_UNLOCK_PKS_HASH_LEN_MISMATCH)
        }
        for i in 0..mci.registers.mci_reg_prod_debug_unlock_pk_hash_reg.len() {
            let word = u32::from_le_bytes(
                prod_dbg_unlock_pks_hashes[i * 4..i * 4 + 4]
                    .try_into()
                    .unwrap_or_else(|_| {
                        fatal_error(McuError::ROM_SOC_PROD_DEBUG_UNLOCK_PKS_HASH_LEN_MISMATCH)
                    }),
            );
            mci.registers.mci_reg_prod_debug_unlock_pk_hash_reg[i].set(word);
        }
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
        }
        // Clear the reset request interrupt
        notif0.modify(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts::SET);
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
}

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
