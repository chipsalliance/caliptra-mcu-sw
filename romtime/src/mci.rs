// Licensed under the Apache-2.0 license

use crate::static_ref::StaticRef;
use registers_generated::mci;
use tock_registers::interfaces::{Readable, Writeable};

pub struct Mci {
    registers: StaticRef<mci::regs::Mci>,
}

impl Mci {
    pub const fn new(registers: StaticRef<mci::regs::Mci>) -> Self {
        Mci { registers }
    }

    pub fn caliptra_boot_go(&self) {
        self.registers.mci_reg_cptra_boot_go.set(1);
    }

    pub fn flow_status(&self) -> u32 {
        self.registers.mci_reg_fw_flow_status.get()
    }

    pub fn hw_flow_status(&self) -> u32 {
        self.registers.mci_reg_hw_flow_status.get()
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
}
