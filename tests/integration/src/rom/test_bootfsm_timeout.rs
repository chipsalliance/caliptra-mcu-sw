// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use caliptra_mcu_error::McuError;
    use caliptra_mcu_hw_model::{InitParams, McuHwModel};
    use caliptra_mcu_otp_lifecycle::LifecycleControllerState;

    #[test]
    fn test_bootfsm_timeout() {
        let binaries = caliptra_mcu_builder::FirmwareBinaries::from_env().unwrap();

        let mut hw = caliptra_mcu_hw_model::new(InitParams {
            caliptra_rom: &binaries.caliptra_rom,
            mcu_rom: &binaries.mcu_rom,
            // This will pause the BootFSM in BOOT_WAIT, so we won't reach DONE
            bootfsm_break: true,
            // Need to be in Dev/Manuf so `bootfsm_break` is respected
            lifecycle_controller_state: Some(LifecycleControllerState::Dev),
            check_booted_to_runtime: false,
            enable_mcu_uart_log: true,
            ..Default::default()
        })
        .unwrap();

        hw.step_until(|m| m.cycle_count() > 11_000_000 || m.mci_fw_fatal_error().is_some());

        let status = hw.mci_fw_fatal_error().expect("Expected a fatal error");
        assert_eq!(u32::from(McuError::ROM_BOOTFSM_TIMEOUT), status);
    }
}
