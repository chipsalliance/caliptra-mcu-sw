// Licensed under the Apache-2.0 license

use capsules_runtime::doe::driver::DoeDriver;
use core::mem::MaybeUninit;
use doe_transport::hil::DoeTransport;
use kernel::capabilities;
use kernel::component::Component;

#[macro_export]
macro_rules! doe_component_static {
    ($T:ty $(,)?) => {{
        let doe_driver = kernel::static_buf!(DoeDriver<'static, $T>);
        (doe_driver,)
    }};
}

pub struct DoeComponent<T: DoeTransport<'static> + 'static> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    doe_transport: &'static T,
}

impl<T: DoeTransport<'static>> DoeComponent<T> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        doe_transport: &'static T,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            doe_transport,
        }
    }
}

impl<T: DoeTransport<'static>> Component for DoeComponent<T> {
    type StaticInput = (&'static mut MaybeUninit<DoeDriver<'static, T>>,);
    type Output = &'static DoeDriver<'static, T>;

    fn finalize(self, static_input: Self::StaticInput) -> Self::Output {
        let grant_cap = kernel::create_capability!(capabilities::MemoryAllocationCapability);

        let doe_driver = static_input.0.write(DoeDriver::new(
            self.doe_transport,
            self.board_kernel.create_grant(self.driver_num, &grant_cap),
        ));

        self.doe_transport.set_tx_client(doe_driver);
        self.doe_transport.set_rx_client(doe_driver);
        self.doe_transport.enable();

        doe_driver
    }
}
