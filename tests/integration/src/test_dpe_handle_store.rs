// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::stop_emulator;
    use random_port::PortPicker;

    #[test]
    fn test_dpe_handle_store() {
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-dpe-handle-store"),
            example_app: true,
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let status = finish_runtime_hw_model(&mut hw);
        assert_eq!(status, 0);

        stop_emulator();
    }
}
