// Licensed under the Apache-2.0 license

//! Reset Reason Register Emulation
//!
//! TODO: This module should eventually be moved to caliptra-sw since the RESET_REASON
//! register is part of the MCI block which belongs in the Caliptra subsystem.
//! Both Caliptra Core and MCU need access to this register.
//!
//! ## Register Access Pattern
//!
//! Per Caliptra SS Hardware Specification (Section: MCU Hitless Update Handshake):
//!
//! - **MCU**: Reads this register to determine boot flow
//! - **Caliptra Core**: Writes to this register to set FW_BOOT_UPD_RESET and FW_HITLESS_UPD_RESET bits
//! - **MCI Hardware**: Automatically sets WARM_RESET bit when a warm reset occurs
//!
//! ## Bit Definitions (from CaliptraSSHardwareSpecification.md)
//!
//! - **WARM_RESET** (bit 2): Set by hardware when a warm reset occurs (mci_rst_b toggles while
//!   mci_pwrgood remains high). Should be cleared by Caliptra Core during firmware update flow.
//!   Per spec: "WARM_RESET will be set by hardware when a warm reset occurs."
//!
//! - **FW_BOOT_UPD_RESET** (bit 1): Set by Caliptra Core to indicate first firmware update
//!   since MCI reset. Cleared by mci_rst_b toggle.
//!
//! - **FW_HITLESS_UPD_RESET** (bit 0): Set by Caliptra Core to indicate second or later
//!   firmware update since MCI reset. Cleared by mci_rst_b toggle.
//!
//! ## Reset Flow (from CaliptraSSIntegrationSpecification.md)
//!
//! When MCU requests a reset via RESET_REQUEST.mcu_req:
//! 1. MCI performs MCU halt req/ack handshake
//! 2. MCI asserts MCU reset (mci_rst_b goes low)
//! 3. If mci_pwrgood remains high, MCI hardware sets WARM_RESET bit
//! 4. MCU comes out of reset and reads RESET_REASON to determine boot flow

use caliptra_emu_bus::ReadWriteRegister;
use registers_generated::mci::bits::ResetReason;
use tock_registers::interfaces::{ReadWriteable, Readable};

/// Emulates the MCI RESET_REASON register behavior
pub struct ResetReasonEmulator {
    /// Reference to the MCI peripheral registers in caliptra-sw
    ext_mci_regs: caliptra_emu_periph::mci::Mci,

    /// Track power state to properly handle warm reset
    pwrgood: bool,
}

impl ResetReasonEmulator {
    /// Create a new reset reason emulator
    pub fn new(ext_mci_regs: caliptra_emu_periph::mci::Mci) -> Self {
        Self {
            ext_mci_regs,
            pwrgood: true,
        }
    }

    /// Get the current register value
    pub fn get(&self) -> u32 {
        self.ext_mci_regs.regs.borrow().reset_reason
    }

    /// Set the register value (for software writes)
    pub fn set(&mut self, value: u32) {
        self.ext_mci_regs.regs.borrow_mut().reset_reason = value;
    }

    /// Handle power down event
    /// When mci_pwrgood goes low, all bits are cleared
    pub fn handle_power_down(&mut self) {
        self.pwrgood = false;
        self.set(0);
    }

    /// Handle power up event
    pub fn handle_power_up(&mut self) {
        self.pwrgood = true;
    }

    /// Handle warm reset event
    /// This is called when mci_rst_b toggles (goes low then high)
    ///
    /// Per hardware spec:
    /// - If pwrgood is high, this is a warm reset and WARM_RESET bit is set
    /// - FW_BOOT_UPD_RESET and FW_HITLESS_UPD_RESET are cleared by mci_rst_b
    pub fn handle_warm_reset(&mut self) {
        // If power is good, this is a warm reset
        if self.pwrgood {
            let reg = ReadWriteRegister::<u32, ResetReason::Register>::new(self.get());
            reg.reg.modify(ResetReason::WarmReset::SET);
            self.set(reg.reg.get());
        }

        // Clear the firmware update bits (these are cleared by mci_rst_b)
        let reg = ReadWriteRegister::<u32, ResetReason::Register>::new(self.get());
        reg.reg
            .modify(ResetReason::FwBootUpdReset::CLEAR + ResetReason::FwHitlessUpdReset::CLEAR);
        self.set(reg.reg.get())
    }
}

impl Default for ResetReasonEmulator {
    fn default() -> Self {
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        Self::new(ext_mci_regs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cold_reset() {
        let mut rr = ResetReasonEmulator::default();

        assert_eq!(rr.get(), 0);
        assert!(rr.pwrgood);

        // Any reset while powered should set WARM_RESET
        rr.handle_warm_reset();
        assert_eq!(rr.get() & (1 << 2), 1 << 2); // bit 2 is WARM_RESET
    }

    #[test]
    fn test_warm_reset() {
        let mut rr = ResetReasonEmulator::default();

        // First reset while powered should set WARM_RESET
        rr.handle_warm_reset();
        assert_eq!(rr.get() & (1 << 2), 1 << 2); // bit 2 should be set

        // Second reset should also set WARM_RESET (it's already set)
        rr.handle_warm_reset();
        assert_eq!(rr.get() & (1 << 2), 1 << 2); // bit 2 should still be set
    }

    #[test]
    fn test_power_cycle() {
        let mut rr = ResetReasonEmulator::default();

        // Set up warm reset condition
        rr.handle_warm_reset();
        assert_eq!(rr.get() & (1 << 2), 1 << 2);

        // Power down should clear everything
        rr.handle_power_down();
        assert_eq!(rr.get(), 0);

        // Power up and first reset after power cycle should set WARM_RESET
        rr.handle_power_up();
        rr.handle_warm_reset();
        assert_eq!(rr.get() & (1 << 2), 1 << 2);
    }

    #[test]
    fn test_software_writes() {
        let mut rr = ResetReasonEmulator::default();

        // Software can set FW update bits
        let reg = ReadWriteRegister::<u32, ResetReason::Register>::new(0);
        reg.reg.modify(ResetReason::FwBootUpdReset::SET);
        rr.set(reg.reg.get());

        assert_eq!(rr.get() & (1 << 1), 1 << 1); // bit 1 is FW_BOOT_UPD_RESET

        // Warm reset should clear FW update bits but set WARM_RESET
        rr.handle_warm_reset();
        assert_eq!(rr.get() & (1 << 1), 0); // FW update bit cleared
        assert_eq!(rr.get() & (1 << 2), 1 << 2); // WARM_RESET bit set
    }
}
