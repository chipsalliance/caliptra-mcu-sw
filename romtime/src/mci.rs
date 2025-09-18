// Licensed under the Apache-2.0 license

use crate::static_ref::StaticRef;
use registers_generated::mci;
use tock_registers::interfaces::{Readable, Writeable};

/// MCU Reset Reason
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum McuResetReason {
    /// Cold Boot - Power-on reset (no bits set)
    ColdBoot,

    /// Warm Reset - MCU reset while power maintained
    WarmReset,

    /// Firmware Boot Update - First firmware update after MCI reset
    FirmwareBootUpdate,

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
    pub fn set_flow_checkpoint(&self, status: u32) {
        let milestone = (self.flow_milestone() as u32) << 24;
        let checkpoint = status & 0x00ff_ffff;
        self.set_flow_status(milestone | checkpoint);
    }

    pub fn flow_checkpoint(&self) -> u32 {
        self.flow_status() & 0x00ff_ffff
    }

    /// Union of current milestones with incoming milestones
    pub fn set_flow_milestone(&self, milestone: u8) {
        let milestone = (milestone as u32) << 24;
        self.set_flow_status(milestone | self.flow_status());
    }

    pub fn flow_milestone(&self) -> u8 {
        (self.flow_status() >> 24) as u8
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
            (false, true, false) => McuResetReason::FirmwareBootUpdate,
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
        self.reset_reason_enum() == McuResetReason::FirmwareBootUpdate
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
        let intr_status = self.read_notif0_intr_trig_r();
        if intr_status & NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK != 0 {
            // Clear interrupt
            self.write_notif0_intr_trig_r(NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK);
            // Request MCU reset
            self.registers.mci_reg_reset_request.set(1); // Any value will trigger reset
        }
    }
}
