// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use crate::jtag::test::ss_setup;

    use caliptra_hw_model::openocd::openocd_jtag_tap::{JtagParams, JtagTap};
    use caliptra_hw_model::HwModel;
    use caliptra_hw_model::DEFAULT_LIFECYCLE_RAW_TOKEN;
    use mcu_hw_model::lcc::{lc_token_to_words, lc_transition, read_lc_state};
    use mcu_rom_common::LifecycleControllerState;

    #[test]
    fn test_raw_unlock() {
        let mut model = ss_setup(
            Some(LifecycleControllerState::Raw),
            /*rma_or_scrap_ppd=*/ false,
            /*debug_intent=*/ false,
            /*bootfsm_break=*/ false,
            /*enable_mcu_uart_log=*/ false,
        );

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
        const RAW_UNLOCK_TOKEN: [u32; 4] = [0xb532a0ca, 0x74ce9687, 0xa2ecef9a, 0x6141be65];
        lc_state = lc_transition(
            &mut *tap,
            LifecycleControllerState::TestUnlocked0,
            Some(RAW_UNLOCK_TOKEN),
        )
        .expect("Unable to transition to TestUnlocked0.");
        println!("Post transition LC state: {}", lc_state);

        // Reset and read the LC state again.
        model.base.cold_reset();
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
        let mut model = ss_setup(
            Some(lc_states[0]),
            /*rma_or_scrap_ppd=*/ false,
            /*debug_intent=*/ false,
            /*bootfsm_break=*/ false,
            /*enable_mcu_uart_log=*/ false,
        );

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
            model.base.cold_reset();
            lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
            println!("LC state after reset: {}", lc_state);
            assert_eq!(lc_state, lc_states[i + 1]);
        }
    }

    #[test]
    fn test_prod_rma_unlock() {
        let mut model = ss_setup(
            Some(LifecycleControllerState::Prod),
            /*rma_or_scrap_ppd=*/ true,
            /*debug_intent=*/ true,
            /*bootfsm_break=*/ false,
            /*enable_mcu_uart_log=*/ false,
        );

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
        assert_eq!(lc_state, LifecycleControllerState::Prod);

        // Perform the RMA LC transition operation.
        lc_state = lc_transition(
            &mut *tap,
            LifecycleControllerState::Rma,
            Some(lc_token_to_words(&DEFAULT_LIFECYCLE_RAW_TOKEN.0)),
        )
        .expect("Unable to transition to RMA.");
        println!("Post transition LC state: {}", lc_state);

        // Reset and read the LC state again.
        model.base.cold_reset();
        lc_state = read_lc_state(&mut *tap).expect("Unable to read LC state.");
        println!("LC state after reset: {}", lc_state);
        assert_eq!(lc_state, LifecycleControllerState::Rma);
    }
}
