// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::McuHwModel;

    #[test]
    fn test_caliptra_mailbox_mbox1_staging() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-caliptra-mailbox-mbox1-staging"),
            example_app: true,
            ..Default::default()
        });

        hw.step_until_exit_success()
            .expect("GET_IMAGE_INFO with MCU MBOX1 staging failed");
    }
}
