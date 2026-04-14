// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use crate::test_hek::test::setup_otp_hek;
    use mcu_hw_model::McuHwModel;

    #[test]
    fn test_handoff_integrity() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut otp = vec![0u8; 4096];
        // Program a valid HEK in slot 2 to verify dynamic state passing
        setup_otp_hek(&mut otp, 2, false, false);

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: false,
            ocp_lock_en: true,
            feature: Some("test-handoff"),
            rom_feature: Some("ocp-lock"),
            ..Default::default()
        });

        hw.step_until_exit_success()
            .expect("HandOff verification failed in runtime");
    }
}
