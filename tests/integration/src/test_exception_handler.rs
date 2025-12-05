//! Licensed under the Apache-2.0 license

//! This module tests Device Ownership Transfer.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_error::McuError;
    use mcu_hw_model::McuHwModel;

    #[test]
    fn test_exception_handler() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-exception-handler"),
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| m.cycle_count() > 10_000_000 || m.mci_fw_fatal_error().is_some());

        let status = hw.mci_fw_fatal_error().unwrap_or(0);
        assert_eq!(u32::from(McuError::GENERIC_EXCEPTION), status);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
