// Licensed under the Apache-2.0 license

// Component for ExternalOTP driver.

use caliptra_mcu_external_otp_driver::hil::ExternalOtp;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;

#[macro_export]
macro_rules! external_otp_component_static {
    () => {{
        let external_otp = kernel::static_buf!(
            caliptra_mcu_capsules_runtime::external_otp::ExternalOtpCapsule<'static>
        );
        external_otp
    }};
}

pub struct ExternalOtpComponent {
    driver: &'static dyn ExternalOtp<'static>,
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
}

impl ExternalOtpComponent {
    pub fn new(
        driver: &'static dyn ExternalOtp<'static>,
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
    ) -> Self {
        Self {
            driver,
            board_kernel,
            driver_num,
        }
    }
}

impl Component for ExternalOtpComponent {
    type StaticInput = &'static mut MaybeUninit<
        caliptra_mcu_capsules_runtime::external_otp::ExternalOtpCapsule<'static>,
    >;

    type Output = &'static caliptra_mcu_capsules_runtime::external_otp::ExternalOtpCapsule<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let external_otp = static_buffer.write(
            caliptra_mcu_capsules_runtime::external_otp::ExternalOtpCapsule::new(
                self.driver,
                self.board_kernel.create_grant(self.driver_num, &grant_cap),
            ),
        );
        // Set the capsule as the client of the OTP driver so it receives callbacks.
        self.driver.set_client(external_otp);
        external_otp
    }
}
