// Licensed under the Apache-2.0 license

// Component for MCI driver.

use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use registers_generated::mci;
use romtime::StaticRef;

pub struct MboxSramComponent {
    registers: StaticRef<mci::regs::Mci>,
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    mem_ref: &'static mut [u32],
}

impl MboxSramComponent {
    pub fn new(
        registers: StaticRef<mci::regs::Mci>,
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        mem_ref: &'static mut [u32],
    ) -> Self {
        Self {
            registers,
            board_kernel,
            driver_num,
            mem_ref,
        }
    }
}

impl Component for MboxSramComponent {
    type StaticInput = &'static mut MaybeUninit<capsules_runtime::mbox_sram::MboxSram>;

    type Output = &'static capsules_runtime::mbox_sram::MboxSram;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        static_buffer.write(capsules_runtime::mbox_sram::MboxSram::new(
            self.driver_num,
            self.registers,
            self.mem_ref,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
        ))
    }
}
