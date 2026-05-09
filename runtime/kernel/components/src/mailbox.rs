// Licensed under the Apache-2.0 license

// Component for mailbox capsule.

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_runtime::dma::hil::Dma as DmaHal;
use capsules_runtime::mailbox::Mailbox;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil::time::Alarm;
use romtime::CaliptraSoC;

#[macro_export]
macro_rules! mailbox_component_static {
    ($A:ty, $b:expr, $c:expr, $d:expr, $e:expr) => {{
        use capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm;
        let alarm = kernel::static_buf!(VirtualMuxAlarm<'static, $A>);
        let caliptra_soc = kernel::static_buf!(CaliptraSoC);
        let mbox = kernel::static_buf!(
            capsules_runtime::mailbox::Mailbox<'static, VirtualMuxAlarm<'static, $A>>
        );
        (alarm, mbox, caliptra_soc, $b, $c, $d, $e)
    }};
}

pub struct MailboxComponent<A: Alarm<'static> + 'static> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    mux_alarm: &'static MuxAlarm<'static, A>,
    dma: &'static dyn DmaHal,
}

impl<A: Alarm<'static>> MailboxComponent<A> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        mux_alarm: &'static MuxAlarm<'static, A>,
        dma: &'static dyn DmaHal,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            mux_alarm,
            dma,
        }
    }
}

impl<A: Alarm<'static>> Component for MailboxComponent<A> {
    type StaticInput = (
        &'static mut MaybeUninit<VirtualMuxAlarm<'static, A>>,
        &'static mut MaybeUninit<Mailbox<'static, VirtualMuxAlarm<'static, A>>>,
        &'static mut MaybeUninit<CaliptraSoC>,
        Option<u32>,
        Option<u32>,
        Option<u32>,
        Option<u64>,
    );

    type Output = &'static Mailbox<'static, VirtualMuxAlarm<'static, A>>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let mux_alarm = static_buffer.0.write(VirtualMuxAlarm::new(self.mux_alarm));
        mux_alarm.setup();

        let caliptra_soc = static_buffer.2.write(CaliptraSoC::new(
            static_buffer.3,
            static_buffer.4,
            static_buffer.5,
        ));

        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let mailbox: &Mailbox<'_, VirtualMuxAlarm<'_, _>> =
            static_buffer
                .1
                .write(capsules_runtime::mailbox::Mailbox::new(
                    mux_alarm,
                    self.board_kernel.create_grant(self.driver_num, &grant_cap),
                    caliptra_soc,
                    static_buffer.6,
                    self.dma,
                ));
        mailbox
    }
}
