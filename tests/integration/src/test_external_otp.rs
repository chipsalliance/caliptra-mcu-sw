// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::stop_emulator;
    use random_port::PortPicker;

    #[test]
    fn test_external_otp() {
        // Instantiate hardware model with external OTP memory loaded.
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-external-otp"),
            example_app: true,
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            ..Default::default()
        });

        hw.start_i3c_controller();

        #[cfg(feature = "fpga_realtime")]
        {
            use crate::test::{
                build_primary_flash_initial_contents, ECC_DEVID_CERT_DER, MLDSA_IDEVID_CERT,
            };
            let primary_flash_initial_contents = build_primary_flash_initial_contents(
                None,
                Some(&ECC_DEVID_CERT_DER),
                Some(&MLDSA_IDEVID_CERT),
                None,
            );
            let mci_ptr = hw.base.mmio.mci().unwrap().ptr as u64;
            crate::test_fpga_flash_ctrl::test::run_imaginary_flash_controller_service_with_init(
                mci_ptr,
                primary_flash_initial_contents,
            );
        }

        // Exit the test.
        let status = finish_runtime_hw_model(&mut hw);
        assert_eq!(status, 0);

        stop_emulator();
    }
}
