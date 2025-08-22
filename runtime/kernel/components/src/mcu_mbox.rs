// Licensed under the Apache-2.0 license

use capsules_runtime::mcu_mbox::McuMboxDriver;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use mcu_mbox_comm::hil;

#[macro_export]
macro_rules! mcu_mbox_component_static {
    ($T:ty $(,)?) => {{
        let mcu_mbox_driver = kernel::static_buf!(McuMboxDriver<'static, $T>);
        (mcu_mbox_driver,)
    }};
}

pub struct McuMboxComponent<T: hil::Mailbox<'static> + 'static> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    physical_driver: &'static T,
}

impl<T: hil::Mailbox<'static>> McuMboxComponent<T> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        physical_driver: &'static T,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            physical_driver,
        }
    }
}

impl<T: hil::Mailbox<'static>> Component for McuMboxComponent<T> {
    type StaticInput = (&'static mut MaybeUninit<McuMboxDriver<'static, T>>,);
    type Output = &'static McuMboxDriver<'static, T>;

    fn finalize(self, static_input: Self::StaticInput) -> Self::Output {
        let grant_cap = kernel::create_capability!(capabilities::MemoryAllocationCapability);
        let mcu_mbox_driver = static_input.0.write(McuMboxDriver::new(
            self.physical_driver,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
        ));

        self.physical_driver.set_client(mcu_mbox_driver);
        self.physical_driver.enable();
        mcu_mbox_driver
    }
}
