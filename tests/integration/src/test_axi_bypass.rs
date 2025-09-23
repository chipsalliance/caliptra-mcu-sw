// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use caliptra_builder::firmware as caliptra_firmware;
    use caliptra_hw_model::BootParams;
    use mcu_builder::firmware;
    use mcu_hw_model::{InitParams, McuHwModel};

    #[test]
    fn test_axi_bypass() {
        let binaries = mcu_builder::FirmwareBinaries::from_env().unwrap();
        let mcu_rom = binaries
            .test_rom(&firmware::hw_model_tests::AXI_BYPASS)
            .unwrap();
        let caliptra_rom = binaries
            .caliptra_test_rom(&caliptra_firmware::driver_tests::AXI_BYPASS)
            .unwrap();
        let init_params = InitParams {
            caliptra_rom: &caliptra_rom,
            mcu_rom: &mcu_rom,
            enable_mcu_uart_log: true,
            ..Default::default()
        };
        let mut model = mcu_hw_model::new(init_params, BootParams::default()).unwrap();
        model.step_until_exit_success().unwrap();
    }
}
