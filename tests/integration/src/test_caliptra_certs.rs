// Licensed under the Apache-2.0 license

//! This module tests Caliptra certificate retrieval and validation.

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::McuHwModel;
    use mcu_rom_common::LifecycleControllerState;
    use random_port::PortPicker;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_caliptra_certs() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-caliptra-certs"),
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            lifecycle_controller_state: Some(LifecycleControllerState::Dev),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, Ordering::Relaxed);
    }
}
