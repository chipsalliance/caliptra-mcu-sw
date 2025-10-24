// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use caliptra_hw_model::lcc::{LcCtrlReg, LcCtrlStatus};
    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap};
    use mcu_builder::FirmwareBinaries;
    use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};
    use mcu_rom_common::LifecycleControllerState;

    #[test]
    fn test_lcc_tap() {
        let firmware_bundle = FirmwareBinaries::from_env().unwrap();
        let lifecycle_controller_state = Some(LifecycleControllerState::TestUnlocked0);

        // Instantiate a CaliptaSS model with OTP empty, emulating a raw device.
        let init_params = InitParams {
            caliptra_rom: &firmware_bundle.caliptra_rom,
            mcu_rom: &firmware_bundle.mcu_rom,
            lifecycle_controller_state,
            ..Default::default()
        };
        let mut model = DefaultHwModel::new_unbooted(init_params).unwrap();

        // Initialize fuses and bring subsystem out of reset.
        model.set_subsystem_reset(false);

        // Connect to LCC JTAG TAP via OpenOCD.
        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };
        let mut tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::LccTap)
            .expect("Failed to connect to the LCC JTAG TAP.");
        let lcc_status = tap
            .read_reg(&LcCtrlReg::Status)
            .expect("Failed to read LCC STATUS register.");
        assert_eq!(
            LcCtrlStatus::from_bits_truncate(lcc_status),
            LcCtrlStatus::INITIALIZED | LcCtrlStatus::READY
        );
    }
}
