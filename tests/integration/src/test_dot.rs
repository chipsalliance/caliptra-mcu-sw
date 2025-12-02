//! Licensed under the Apache-2.0 license

//! This module tests Device Ownership Transfer.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_error::McuError;
    use mcu_hw_model::McuHwModel;

    #[test]
    fn test_dot_blob_corrupt() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(vec![0x12; 4096]),
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| m.cycle_count() > 10_000_000 || m.mci_fw_fatal_error().is_some());

        let status = hw.mci_fw_fatal_error().unwrap_or(0);
        assert_eq!(
            u32::from(McuError::ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR),
            status
        );

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
