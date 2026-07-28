// Licensed under the Apache-2.0 license

//! Integration test for VeeR InternalTimers get_alarm() bug on FPGA.

#[cfg(feature = "fpga_realtime")]
#[cfg(test)]
pub mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use std::sync::atomic::Ordering;

    /// Test that the fire_at fix makes get_alarm() return correct values.
    ///
    /// The kernel-side test (timer_alarm_test.rs) creates two VirtualMuxAlarms,
    /// lets the first timer expire, then calls set_alarm() on the second.
    /// With the fix, Guard 1 correctly passes and hardware is reprogrammed.
    ///
    /// Exit 0 → hardware correctly reprogrammed (fix applied, PASS)
    /// Exit 1 → hardware NOT reprogrammed (bug present, FAIL)
    #[test]
    pub fn test_get_alarm_expired_fpga() {
        let feature = "test-get-alarm-expired";
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(feature),
            ..Default::default()
        });

        let result = finish_runtime_hw_model(&mut hw);

        caliptra_mcu_testing_common::stop_emulator();

        assert_eq!(
            0, result,
            "Test failed: hardware was NOT reprogrammed for VA2 (get_alarm() returned bogus value)"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
