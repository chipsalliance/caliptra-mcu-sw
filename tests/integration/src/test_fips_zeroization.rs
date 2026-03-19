// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::{McuHwModel, McuManager};
    use std::sync::atomic::Ordering;

    const MAX_ZEROIZATION_CYCLES: u64 = 500_000_000;

    /// Test that the FIPS zeroization flow writes 0xFFFF_FFFF to the
    /// FC_FIPS_ZEROZATION mask register on cold boot when the PPD signal
    /// is asserted.
    ///
    /// The ROM detects the PPD signal early in the cold-boot flow and sets
    /// the mask before `SS_CONFIG_DONE_STICKY` locks the register.
    #[test]
    fn test_fips_zeroization_cold_boot() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_only: true,
            fips_zeroization: true,
            ..Default::default()
        });

        // Poll until the ROM writes the zeroization mask or we time out.
        //
        // We cannot use `mci_boot_checkpoint() >= FipsZeroizationComplete`
        // because boot-flow checkpoint values (e.g. ColdBootFlowStarted =
        // 385) are numerically larger than the zeroization checkpoints and
        // would satisfy the condition before the mask is actually written.
        hw.step_until(|hw| {
            let mask = hw
                .mcu_manager()
                .with_mci(|mci| mci.fc_fips_zerozation().read());
            mask == 0xFFFF_FFFF || hw.cycle_count() >= MAX_ZEROIZATION_CYCLES
        });

        let mask = hw
            .mcu_manager()
            .with_mci(|mci| mci.fc_fips_zerozation().read());
        assert_eq!(
            mask, 0xFFFF_FFFF,
            "FC_FIPS_ZEROZATION mask should be 0xFFFF_FFFF, got {:#010x}",
            mask,
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
