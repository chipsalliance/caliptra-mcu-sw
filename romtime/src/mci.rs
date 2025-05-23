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
}
