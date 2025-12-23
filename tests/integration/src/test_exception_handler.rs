//! Licensed under the Apache-2.0 license

//! This module tests Device Ownership Transfer.

#[cfg(test)]
mod test {
    use crate::{platform, test::TEST_LOCK};
    use caliptra_hw_model::BootParams;
    use mcu_builder::firmware;
    use mcu_error::McuError;
    use mcu_hw_model::{InitParams, McuHwModel};

    #[test]
    fn test_exception_handler() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mcu_rom = if let Ok(binaries) = mcu_builder::FirmwareBinaries::from_env() {
            binaries
                .test_rom(&firmware::hw_model_tests::EXCEPTION_HANDLER)
                .unwrap()
        } else {
            let rom_file = mcu_builder::test_rom_build(
                Some(platform()),
                &firmware::hw_model_tests::EXCEPTION_HANDLER,
            )
            .unwrap();
            std::fs::read(&rom_file).unwrap()
        };

        let mut hw = mcu_hw_model::new(
            InitParams {
                mcu_rom: &mcu_rom,
                check_booted_to_runtime: false,
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        hw.step_until(|m| m.cycle_count() > 10_000_000 || m.mci_fw_fatal_error().is_some());

        let status = hw.mci_fw_fatal_error().unwrap_or(0);
        assert_eq!(u32::from(McuError::GENERIC_EXCEPTION), status);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
