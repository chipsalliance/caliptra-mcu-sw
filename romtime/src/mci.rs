// Licensed under the Apache-2.0 license

use crate::static_ref::StaticRef;
use registers_generated::mci;
use registers_generated::mci::bits::ResetRequest;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

/// MCU Reset Reason
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum McuResetReason {
    /// Cold Boot - Power-on reset (no bits set)
    ColdBoot,

    /// Warm Reset - MCU reset while power maintained
    WarmReset,

    /// Firmware Boot Update - First firmware update after MCI reset
    FirmwareBootReset,

    /// Firmware Hitless Update - Second or later firmware update
    FirmwareHitlessUpdate,

    /// Multiple bits set - invalid state
    Invalid,
}

pub struct Mci {
    pub registers: StaticRef<mci::regs::Mci>,
}

impl Mci {
    pub const fn new(registers: StaticRef<mci::regs::Mci>) -> Self {
        Mci { registers }
    }

    pub fn device_lifecycle_state(&self) -> mci::bits::SecurityState::DeviceLifecycle::Value {
        self.registers
            .mci_reg_security_state
            .read_as_enum(mci::bits::SecurityState::DeviceLifecycle)
            .unwrap_or(mci::bits::SecurityState::DeviceLifecycle::Value::DeviceUnprovisioned)
    }

    pub fn security_state(&self) -> u32 {
        self.registers.mci_reg_security_state.get()
    }

    pub fn caliptra_boot_go(&self) {
        self.registers.mci_reg_cptra_boot_go.set(1);
    }

    pub fn set_flow_status(&self, status: u32) {
        self.registers.mci_reg_fw_flow_status.set(status);
    }

    pub fn flow_status(&self) -> u32 {
        self.registers.mci_reg_fw_flow_status.get()
    }

    /// Overwrite current checkpoint, but not the milestone
    pub fn set_flow_checkpoint(&self, checkpoint: u16) {
        let milestone = u32::from(self.flow_milestone()) << 16;
        self.set_flow_status(milestone | u32::from(checkpoint));
    }

    pub fn flow_checkpoint(&self) -> u16 {
        (self.flow_status() & 0x0000_ffff) as u16
    }

    pub fn set_fw_fatal_error(&self, code: u32) {
        self.registers.mci_reg_fw_error_fatal.set(code);
    }

    /// Union of current milestones with incoming milestones
    pub fn set_flow_milestone(&self, milestone: u16) {
        let milestone = u32::from(milestone) << 16;
        self.set_flow_status(milestone | self.flow_status());
    }

    pub fn flow_milestone(&self) -> u16 {
        (self.flow_status() >> 16) as u16
    }

    pub fn hw_flow_status(&self) -> u32 {
        self.registers.mci_reg_hw_flow_status.get()
    }

    pub fn set_nmi_vector(&self, nmi_vector: u32) {
        self.registers.mci_reg_mcu_nmi_vector.set(nmi_vector);
    }

    pub fn configure_wdt(&self, wdt1_timeout: u32, wdt2_timeout: u32) {
        // Set WDT1 period.
        self.registers.mci_reg_wdt_timer1_timeout_period[0].set(wdt1_timeout);
        self.registers.mci_reg_wdt_timer1_timeout_period[1].set(0);

        // Set WDT2 period. Fire immediately after WDT1 expiry
        self.registers.mci_reg_wdt_timer2_timeout_period[0].set(wdt2_timeout);
        self.registers.mci_reg_wdt_timer2_timeout_period[1].set(0);

        // Enable WDT1 only. WDT2 is automatically scheduled (since it is disabled) on WDT1 expiry.
        self.registers.mci_reg_wdt_timer1_ctrl.set(1); // Timer1Restart
        self.registers.mci_reg_wdt_timer1_en.set(1); // Timer1En
    }

    pub fn disable_wdt(&self) {
        self.registers.mci_reg_wdt_timer1_en.set(0); // Timer1En CLEAR
    }

    /// Read the reset reason register value
    pub fn reset_reason(&self) -> u32 {
        self.registers.mci_reg_reset_reason.get()
    }

    /// Get the reset reason as an enum
    pub fn reset_reason_enum(&self) -> McuResetReason {
        let warm_reset = self
            .registers
            .mci_reg_reset_reason
            .read(mci::bits::ResetReason::WarmReset)
            != 0;
        let fw_boot_upd = self
            .registers
            .mci_reg_reset_reason
            .read(mci::bits::ResetReason::FwBootUpdReset)
            != 0;
        let fw_hitless_upd = self
            .registers
            .mci_reg_reset_reason
            .read(mci::bits::ResetReason::FwHitlessUpdReset)
            != 0;

        match (warm_reset, fw_boot_upd, fw_hitless_upd) {
            (false, false, false) => McuResetReason::ColdBoot,
            (true, false, false) => McuResetReason::WarmReset,
            (false, true, false) => McuResetReason::FirmwareBootReset,
            (false, false, true) => McuResetReason::FirmwareHitlessUpdate,
            _ => McuResetReason::Invalid,
        }
    }

    /// Check if this is a cold reset (power-on reset)
    pub fn is_cold_reset(&self) -> bool {
        self.reset_reason_enum() == McuResetReason::ColdBoot
    }

    /// Check if this is a warm reset
    pub fn is_warm_reset(&self) -> bool {
        self.reset_reason_enum() == McuResetReason::WarmReset
    }

    /// Check if this is a firmware boot update reset
    pub fn is_fw_boot_update_reset(&self) -> bool {
        self.reset_reason_enum() == McuResetReason::FirmwareBootReset
    }

    /// Check if this is a firmware hitless update reset
    pub fn is_fw_hitless_update_reset(&self) -> bool {
        self.reset_reason_enum() == McuResetReason::FirmwareHitlessUpdate
    }

    pub fn read_notif0_intr_trig_r(&self) -> u32 {
        self.registers.intr_block_rf_notif0_intr_trig_r.get()
    }

    pub fn write_notif0_intr_trig_r(&self, value: u32) {
        self.registers.intr_block_rf_notif0_intr_trig_r.set(value);
    }

    pub fn read_wdt_timer1_en(&self) -> u32 {
        self.registers.mci_reg_wdt_timer1_en.get()
    }
    pub fn write_wdt_timer1_en(&self, value: u32) {
        self.registers.mci_reg_wdt_timer1_en.set(value);
    }

    // Interrupt handler for MCI interrupts
    /// This function checks the MCI interrupt status registers
    /// and determines which interrupt has occurred.
    /// The interrupt handler is responsible for clearing the interrupt
    /// and performing the necessary actions based on the interrupt type.
    pub fn handle_interrupt(&self) {
        const NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK: u32 = 0x2;
        let intr_status = self.registers.intr_block_rf_notif0_internal_intr_r.get();
        if intr_status & NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK != 0 {
            // Clear interrupt
            self.registers
                .intr_block_rf_notif0_internal_intr_r
                .modify(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts::SET);
            // Request MCU reset
            self.registers
                .mci_reg_reset_request
                .modify(ResetRequest::McuReq::SET);
        }
    }

    pub fn trigger_warm_reset(&self) {
        self.registers.mci_reg_reset_request.set(1);
    }

    /// Sets the SS_CONFIG_DONE_STICKY register to lock configuration registers.
    /// Once set, certain registers (like PROD_DEBUG_UNLOCK_PK_HASH) become read-only
    /// until the next cold reset.
    pub fn set_ss_config_done_sticky(&self) {
        self.registers
            .mci_reg_ss_config_done_sticky
            .write(mci::bits::SsConfigDone::Done::SET);
    }

    /// Checks if SS_CONFIG_DONE_STICKY is set
    pub fn is_ss_config_done_sticky(&self) -> bool {
        self.registers
            .mci_reg_ss_config_done_sticky
            .is_set(mci::bits::SsConfigDone::Done)
    }

    /// Sets the SS_CONFIG_DONE register to lock configuration registers.
    /// Once set, certain registers become read-only until the next warm reset.
    pub fn set_ss_config_done(&self) {
        self.registers
            .mci_reg_ss_config_done
            .write(mci::bits::SsConfigDone::Done::SET);
    }

    /// Checks if SS_CONFIG_DONE is set
    pub fn is_ss_config_done(&self) -> bool {
        self.registers
            .mci_reg_ss_config_done
            .is_set(mci::bits::SsConfigDone::Done)
    }

    /// Read the production debug unlock PK hash register at the given index
    pub fn read_prod_debug_unlock_pk_hash(&self, index: usize) -> Option<u32> {
        self.registers
            .mci_reg_prod_debug_unlock_pk_hash_reg
            .get(index)
            .map(|reg| reg.get())
    }

    /// Get the length of the production debug unlock PK hash register array
    pub fn prod_debug_unlock_pk_hash_len(&self) -> usize {
        self.registers.mci_reg_prod_debug_unlock_pk_hash_reg.len()
    }

    /// Read the MCU mailbox 0 valid AXI user register at the given index
    pub fn read_mbox0_valid_axi_user(&self, index: usize) -> Option<u32> {
        self.registers
            .mci_reg_mbox0_valid_axi_user
            .get(index)
            .map(|reg| reg.get())
    }

    /// Read the MCU mailbox 0 AXI user lock register at the given index
    pub fn read_mbox0_axi_user_lock(&self, index: usize) -> Option<bool> {
        self.registers
            .mci_reg_mbox0_axi_user_lock
            .get(index)
            .map(|reg| reg.is_set(mci::bits::MboxxAxiUserLock::Lock))
    }

    /// Read the MCU mailbox 1 valid AXI user register at the given index
    pub fn read_mbox1_valid_axi_user(&self, index: usize) -> Option<u32> {
        self.registers
            .mci_reg_mbox1_valid_axi_user
            .get(index)
            .map(|reg| reg.get())
    }

    /// Read the MCU mailbox 1 AXI user lock register at the given index
    pub fn read_mbox1_axi_user_lock(&self, index: usize) -> Option<bool> {
        self.registers
            .mci_reg_mbox1_axi_user_lock
            .get(index)
            .map(|reg| reg.is_set(mci::bits::MboxxAxiUserLock::Lock))
    }

    /// Get the length of the MCU mailbox AXI user register arrays
    pub fn mbox_axi_user_len(&self) -> usize {
        self.registers.mci_reg_mbox0_valid_axi_user.len()
    }

    /// Write to the MCU mailbox 0 valid AXI user register at the given index
    pub fn write_mbox0_valid_axi_user(&self, index: usize, value: u32) -> bool {
        if let Some(reg) = self.registers.mci_reg_mbox0_valid_axi_user.get(index) {
            reg.set(value);
            true
        } else {
            false
        }
    }

    /// Lock the MCU mailbox 0 AXI user register at the given index
    pub fn lock_mbox0_axi_user(&self, index: usize) -> bool {
        if let Some(reg) = self.registers.mci_reg_mbox0_axi_user_lock.get(index) {
            reg.write(mci::bits::MboxxAxiUserLock::Lock::SET);
            true
        } else {
            false
        }
    }

    /// Write to the MCU mailbox 1 valid AXI user register at the given index
    pub fn write_mbox1_valid_axi_user(&self, index: usize, value: u32) -> bool {
        if let Some(reg) = self.registers.mci_reg_mbox1_valid_axi_user.get(index) {
            reg.set(value);
            true
        } else {
            false
        }
    }

    /// Lock the MCU mailbox 1 AXI user register at the given index
    pub fn lock_mbox1_axi_user(&self, index: usize) -> bool {
        if let Some(reg) = self.registers.mci_reg_mbox1_axi_user_lock.get(index) {
            reg.write(mci::bits::MboxxAxiUserLock::Lock::SET);
            true
        } else {
            false
        }
    }
}
