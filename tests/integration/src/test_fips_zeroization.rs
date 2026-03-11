// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::McuHwModel;
    use mcu_rom_common::McuRomBootStatus;
    use std::sync::atomic::Ordering;

    const MAX_ZEROIZATION_CYCLES: u64 = 500_000_000;

    /// Test that the FIPS zeroization flow triggers on cold boot when the
    /// PPD signal is asserted, and that the ROM reaches the expected
    /// FipsZeroizationDetected checkpoint.
    ///
    /// NOTE: We check `FipsZeroizationDetected` rather than
    /// `FipsZeroizationComplete` because the emulated Caliptra DMA cannot
    /// access fuse-controller OTP, so ZEROIZE_UDS_FE panics in the model.
    /// Extend to `FipsZeroizationComplete` once the emulator supports it.
    #[test]
    fn test_fips_zeroization_cold_boot() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_only: true,
            fips_zeroization: true,
            ..Default::default()
        });

        let expected_checkpoint = McuRomBootStatus::FipsZeroizationDetected as u16;

        hw.step_until(|hw| {
            let checkpoint = hw.mci_boot_checkpoint();
            checkpoint >= expected_checkpoint || hw.cycle_count() >= MAX_ZEROIZATION_CYCLES
        });

        let checkpoint = hw.mci_boot_checkpoint();
        assert!(
            checkpoint >= expected_checkpoint,
            "ROM should reach FipsZeroizationDetected checkpoint (expected >= {}, got {})",
            expected_checkpoint,
            checkpoint
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
