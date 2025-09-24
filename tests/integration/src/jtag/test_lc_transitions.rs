// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap};
    use caliptra_hw_model::Fuses;
    use caliptra_hw_model::DEFAULT_LIFECYCLE_RAW_TOKEN;
    use mcu_builder::FirmwareBinaries;
    use mcu_hw_model::lcc::{lc_token_to_words, lc_transition, read_lc_state};
    use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};
    use mcu_rom_common::LifecycleControllerState;

    fn ss_setup(initial_lc_state: Option<LifecycleControllerState>) -> DefaultHwModel {
        let firmware_bundle = FirmwareBinaries::from_env().unwrap();

        let init_params = InitParams {
            caliptra_rom: &firmware_bundle.caliptra_rom,
            mcu_rom: &firmware_bundle.mcu_rom,
            lifecycle_controller_state: initial_lc_state,
            ..Default::default()
        };
        let mut model = DefaultHwModel::new_unbooted(init_params).unwrap();
        model.init_fuses(&Fuses::default());
        model.set_subsystem_reset(false);
        model
    }

    #[test]
    fn test_raw_unlock() {
        let mut model = ss_setup(Some(LifecycleControllerState::Raw));

        // Connect to LCC JTAG TAP via OpenOCD.
        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };
        let mut tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::LccTap)
            .expect("Failed to connect to the LCC JTAG TAP.");

        // Read the LC state.
        let mut lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
        println!("Initial LC state: {}", lc_state);
        assert_eq!(lc_state, LifecycleControllerState::Raw);

        // Perform the raw unlock LC transition operation.
        const RAW_UNLOCK_TOKEN: [u32; 4] = [0xef1fadea, 0xadfc9693, 0x421748a2, 0xf12a5911];
        lc_state = lc_transition(
            &mut *tap,
            LifecycleControllerState::TestUnlocked0,
            Some(RAW_UNLOCK_TOKEN),
        )
        .expect("Unable to transition to TestUnlocked0.");
        println!("Post transition LC state: {}", lc_state);

        // Reset and read the LC state again.
        model.set_subsystem_reset(true);
        model.set_subsystem_reset(false);
        lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
        println!("LC state after reset: {}", lc_state);
        assert_eq!(lc_state, LifecycleControllerState::TestUnlocked0);
    }

    #[test]
    fn test_lc_walkthrough() {
        let lc_states = vec![
            LifecycleControllerState::TestUnlocked0,
            LifecycleControllerState::TestLocked0,
            LifecycleControllerState::TestUnlocked1,
            LifecycleControllerState::TestLocked1,
            LifecycleControllerState::TestUnlocked2,
            LifecycleControllerState::TestLocked2,
            LifecycleControllerState::TestUnlocked3,
            LifecycleControllerState::TestLocked3,
            LifecycleControllerState::TestUnlocked4,
            LifecycleControllerState::TestLocked4,
            LifecycleControllerState::TestUnlocked5,
            LifecycleControllerState::TestLocked5,
            LifecycleControllerState::TestUnlocked6,
            LifecycleControllerState::TestLocked6,
            LifecycleControllerState::TestUnlocked7,
            LifecycleControllerState::Dev,
            LifecycleControllerState::Prod,
        ];

        // Initialize Caliptra SS in first LC state.
        let mut model = ss_setup(Some(lc_states[0]));

        // Connect to LCC JTAG TAP via OpenOCD.
        let jtag_params = JtagParams {
            openocd: PathBuf::from("openocd"),
            adapter_speed_khz: 1000,
            log_stdio: true,
        };
        let mut tap = model
            .jtag_tap_connect(&jtag_params, JtagTap::LccTap)
            .expect("Failed to connect to the LCC JTAG TAP.");

        // Iterate over the LC states, transitioning to each one.
        for i in 0..lc_states.len() - 1 {
            let mut lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
            println!("Initial LC state: {}", lc_state);
            assert_eq!(lc_state, lc_states[i]);
            let token = match lc_state {
                LifecycleControllerState::TestLocked0
                | LifecycleControllerState::TestLocked1
                | LifecycleControllerState::TestLocked2
                | LifecycleControllerState::TestLocked3
                | LifecycleControllerState::TestLocked4
                | LifecycleControllerState::TestLocked5
                | LifecycleControllerState::TestLocked6
                | LifecycleControllerState::TestUnlocked7
                | LifecycleControllerState::Dev => {
                    Some(lc_token_to_words(&DEFAULT_LIFECYCLE_RAW_TOKEN.0))
                }
                _ => None,
            };
            lc_state = lc_transition(&mut *tap, lc_states[i + 1], token)
                .expect("Unable to transition to TestUnlocked0.");
            println!("Post transition LC state: {}", lc_state);

            // Reset and read the LC state again.
            model.set_subsystem_reset(true);
            model.set_subsystem_reset(false);
            lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
            println!("LC state after reset: {}", lc_state);
            assert_eq!(lc_state, lc_states[i + 1]);
        }
    }
}
