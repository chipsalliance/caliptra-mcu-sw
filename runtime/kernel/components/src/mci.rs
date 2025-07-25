// Licensed under the Apache-2.0 license

// Component for MCI driver.

use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use registers_generated::mci;
use romtime::StaticRef;

#[macro_export]
macro_rules! mci_component_static {
    ($b:expr) => {{
        let mci = kernel::static_buf!(capsules_runtime::mci::Mci);
        let driver = kernel::static_buf!(romtime::Mci);
        (mci, driver, $b)
    }};
}

pub struct MciComponent {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
}

impl MciComponent {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
        }
    }
}

impl Component for MciComponent {
    type StaticInput = (
        &'static mut MaybeUninit<capsules_runtime::mci::Mci>,
        &'static mut MaybeUninit<romtime::Mci>,
        StaticRef<mci::regs::Mci>,
    );

    type Output = &'static capsules_runtime::mci::Mci;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let mci_driver = static_buffer.1.write(romtime::Mci::new(
            static_buffer.2,
        ));        
        let mci: &capsules_runtime::mci::Mci =
            static_buffer.0.write(capsules_runtime::mci::Mci::new(
                mci_driver,
                self.board_kernel.create_grant(self.driver_num, &grant_cap),
            ));
        mci
    }
}
