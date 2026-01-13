//! Licensed under the Apache-2.0 license

//! This module tests the I3C simple enable/disable functionality

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::McuHwModel;
    use random_port::PortPicker;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_i3c_simple() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-i3c-simple"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, Ordering::Relaxed);
    }
}
