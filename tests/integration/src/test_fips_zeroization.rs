// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::{McuHwModel, McuManager};
    use mcu_rom_common::McuRomBootStatus;
    use std::sync::atomic::Ordering;

    const MAX_ZEROIZATION_CYCLES: u64 = 500_000_000;

    /// Test that the FIPS zeroization flow completes on cold boot when the
    /// PPD signal is asserted.
    ///
    /// The ROM should detect the PPD signal, command Caliptra to zeroize
    /// UDS and field entropy via ZEROIZE_UDS_FE, write 0xFFFF_FFFF to the
    /// FC_FIPS_ZEROZATION mask register, request an LC transition to SCRAP,
    /// and halt.
    #[test]
    fn test_fips_zeroization_cold_boot() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_only: true,
            fips_zeroization: true,
            ..Default::default()
        });

        let expected_checkpoint = McuRomBootStatus::FipsZeroizationComplete as u16;

        hw.step_until(|hw| {
            hw.mci_boot_checkpoint() >= expected_checkpoint
                || hw.cycle_count() >= MAX_ZEROIZATION_CYCLES
        });

        let checkpoint = hw.mci_boot_checkpoint();
        assert!(
            checkpoint >= expected_checkpoint,
            "ROM should reach FipsZeroizationComplete checkpoint (expected >= {}, got {})",
            expected_checkpoint,
            checkpoint,
        );

        // Verify the ROM wrote 0xFFFF_FFFF to the MCI zeroization mask
        // register, authorizing the fuse controller to zeroize non-secret
        // fuse partitions.
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
