// Licensed under the Apache-2.0 license

// Component for MCI driver.

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil::time::Alarm;
use registers_generated::mci;
use romtime::StaticRef;

#[macro_export]
macro_rules! mbox_sram_component_static {
    ($A:ty) => {{
        use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
        let alarm = kernel::static_buf!(VirtualMuxAlarm<'static, $A>);
        let mbox_sram = kernel::static_buf!(
            capsules_runtime::mbox_sram::MboxSram<'static, VirtualMuxAlarm<'static, $A>>
        );
        (alarm, mbox_sram)
    }};
}

pub struct MboxSramComponent<A: Alarm<'static> + 'static> {
    registers: StaticRef<mci::regs::Mci>,
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    mem_ref: &'static mut [u32],
    mux_alarm: &'static MuxAlarm<'static, A>,
}

impl<A: Alarm<'static> + 'static> MboxSramComponent<A> {
    pub fn new(
        registers: StaticRef<mci::regs::Mci>,
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        mem_ref: &'static mut [u32],
        mux_alarm: &'static MuxAlarm<'static, A>,
    ) -> Self {
        Self {
            registers,
            board_kernel,
            driver_num,
            mem_ref,
            mux_alarm,
        }
    }
}

impl<A: Alarm<'static> + 'static> Component for MboxSramComponent<A> {
    type StaticInput = (
        &'static mut MaybeUninit<VirtualMuxAlarm<'static, A>>,
        &'static mut MaybeUninit<
            capsules_runtime::mbox_sram::MboxSram<'static, VirtualMuxAlarm<'static, A>>,
        >,
    );

    type Output =
        &'static capsules_runtime::mbox_sram::MboxSram<'static, VirtualMuxAlarm<'static, A>>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let mux_alarm = static_buffer.0.write(VirtualMuxAlarm::new(self.mux_alarm));
        mux_alarm.setup();
        let mbox_sram = static_buffer
            .1
            .write(capsules_runtime::mbox_sram::MboxSram::new(
                self.driver_num,
                self.registers,
                self.mem_ref,
                self.board_kernel.create_grant(self.driver_num, &grant_cap),
                mux_alarm,
            ));
        mbox_sram.init();
        mbox_sram
    }
}
