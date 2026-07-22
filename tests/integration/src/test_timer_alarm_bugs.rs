// Licensed under the Apache-2.0 license

//! Integration test for VirtualMuxAlarm set_alarm() race condition on FPGA.

#[cfg(feature = "fpga_realtime")]
#[cfg(test)]
pub mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use std::sync::atomic::Ordering;

    /// Test that demonstrates the VirtualMuxAlarm set_alarm() race condition.
    ///
    /// When one VirtualMuxAlarm's timer expires but MuxAlarm::alarm() hasn't been
    /// called yet, a second VirtualMuxAlarm's set_alarm() sees stale next_tick_vals
    /// and skips reprogramming the hardware timer.
    ///
    /// Exit 0 → hardware correctly reprogrammed (fix applied, PASS)
    /// Exit 1 → hardware NOT reprogrammed (bug present, FAIL)
    #[test]
    #[ignore] // Run manually with --include-ignored on FPGA
    pub fn test_alarm_race_condition_fpga() {
        let feature = "test-alarm-race-condition";
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
            "Test failed: hardware was NOT reprogrammed for VA2 (stale guards bug present)"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
