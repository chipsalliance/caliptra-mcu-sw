// Licensed under the Apache-2.0 license

// Component for MCI driver.

use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;

pub struct MciComponent {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    driver: &'static romtime::Mci,
}

impl MciComponent {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        driver: &'static romtime::Mci,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            driver,
        }
    }
}

impl Component for MciComponent {
    type StaticInput = &'static mut MaybeUninit<capsules_runtime::mci::Mci>;

    type Output = &'static capsules_runtime::mci::Mci;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let mci: &capsules_runtime::mci::Mci =
            static_buffer.write(capsules_runtime::mci::Mci::new(
                self.driver,
                self.board_kernel.create_grant(self.driver_num, &grant_cap),
            ));
        mci
    }
}
