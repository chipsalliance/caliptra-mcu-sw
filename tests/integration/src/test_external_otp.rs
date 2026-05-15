// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::MCU_RUNNING;
    use random_port::PortPicker;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_external_otp() {
        // Create external OTP memory contents with 0xCAFEBEEF and 0xFEEDB0B0 at the start.
        let mut external_otp_data = vec![0x00u8; 1024];
        external_otp_data[0..4].copy_from_slice(&0xCAFEBEEFu32.to_le_bytes());
        external_otp_data[4..8].copy_from_slice(&0xFEEDB0B0u32.to_le_bytes());

        // Instantiate hardware model with external OTP memory loaded.
        let mut hw = start_runtime_hw_model(TestParams {
            external_otp_memory: Some(external_otp_data),
            feature: Some("test-external-otp"),
            example_app: true,
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            ..Default::default()
        });

        hw.start_i3c_controller();

        // Exit the test.
        let status = finish_runtime_hw_model(&mut hw);
        assert_eq!(status, 0);

        MCU_RUNNING.store(false, Ordering::Relaxed);
    }
}
