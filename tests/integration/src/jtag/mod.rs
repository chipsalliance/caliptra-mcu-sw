// Licensed under the Apache-2.0 license

mod test_jtag_taps;
mod test_lc_transitions;
mod test_manuf_debug_unlock;
mod test_uds;

#[cfg(test)]
mod test {
    use caliptra_hw_model::Fuses;
    use mcu_builder::FirmwareBinaries;
    use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};
    use mcu_rom_common::LifecycleControllerState;

    pub fn ss_setup(
        initial_lc_state: Option<LifecycleControllerState>,
        debug_intent: bool,
        bootfsm_break: bool,
        enable_mcu_uart_log: bool,
    ) -> DefaultHwModel {
        let firmware_bundle = FirmwareBinaries::from_env().unwrap();

        let init_params = InitParams {
            caliptra_rom: &firmware_bundle.caliptra_rom,
            mcu_rom: &firmware_bundle.mcu_rom,
            lifecycle_controller_state: initial_lc_state,
            debug_intent,
            bootfsm_break,
            enable_mcu_uart_log,
            ..Default::default()
        };
        let mut model = DefaultHwModel::new_unbooted(init_params).unwrap();
        model
            .base
            .init_otp(&Fuses::default())
            .expect("Failed to init OTP.");
        model
    }
}
