// Licensed under the Apache-2.0 license

// Component for OTP driver.

use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;

pub struct OtpComponent {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    total_heks: u32,
    driver: &'static romtime::Otp,
}

impl OtpComponent {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        total_heks: u32,
        driver: &'static romtime::Otp,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            total_heks,
            driver,
        }
    }
}

impl Component for OtpComponent {
    type StaticInput = &'static mut MaybeUninit<capsules_runtime::otp::Otp>;

    type Output = &'static capsules_runtime::otp::Otp;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let otp: &capsules_runtime::otp::Otp =
            static_buffer.write(capsules_runtime::otp::Otp::new(
                self.driver,
                self.total_heks,
                self.board_kernel.create_grant(self.driver_num, &grant_cap),
            ));
        otp
    }
}
