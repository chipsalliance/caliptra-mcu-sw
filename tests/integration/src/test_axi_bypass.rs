// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use caliptra_builder::firmware as caliptra_firmware;
    use caliptra_mcu_builder::firmware;
    use caliptra_mcu_hw_model::{InitParams, McuHwModel};

    #[test]
    fn test_axi_bypass() {
        let binaries = caliptra_mcu_builder::FirmwareBinaries::from_env().unwrap();
        let bundle = binaries.as_bundle(&caliptra_mcu_builder::firmware::targets::TEST_AXI_BYPASS);
        let init_params = InitParams {
            enable_mcu_uart_log: true,
            ..InitParams::from_bundle(bundle)
        };
        let mut model = caliptra_mcu_hw_model::new(init_params).unwrap();
        model.step_until_exit_success().unwrap();
    }
}
