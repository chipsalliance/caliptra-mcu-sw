// Licensed under the Apache-2.0 license

//! Integration tests that boot a parameterized test ROM to perform
//! LC state transitions from the MCU CPU.

#[cfg(test)]
mod test {
    use crate::platform;
    use caliptra_mcu_builder::firmware;
    use caliptra_mcu_hw_model::{InitParams, McuHwModel, McuManager};
    use caliptra_mcu_rom_common::LifecycleControllerState;

    fn load_roms() -> (Vec<u8>, Vec<u8>) {
        if let Ok(binaries) = caliptra_mcu_builder::FirmwareBinaries::from_env() {
            (
                binaries.caliptra_rom.clone(),
                binaries
                    .test_rom(&firmware::hw_model_tests::LC_CTRL)
                    .unwrap(),
            )
        } else {
            let rom_file =
                caliptra_mcu_builder::test_rom_build(&caliptra_mcu_builder::CaliptraBuildArgs {
                    platform: Some(platform()),
                    fwid: Some(&firmware::hw_model_tests::LC_CTRL),
                    ..Default::default()
                })
                .unwrap();
            (vec![], std::fs::read(&rom_file).unwrap())
        }
    }

    /// Token type for LC transitions.
    #[derive(Clone, Copy)]
    enum TokenType {
        /// All-zero token (unconditional transitions).
        None = 0,
        /// Raw unlock token (Raw → TestUnlocked0).
        RawUnlock = 1,
        /// Default OTP token (provisioned by hw-model).
        Default = 2,
    }

    /// Encode transition parameters into generic_input_wires[0].
    /// Layout: bit 0 = go, bits [12:8] = target state index,
    ///         bits [16:15] = token type, bit 17 = expect error.
    fn encode_wires(target: LifecycleControllerState, token: TokenType, expect_error: bool) -> u32 {
        let go = 1u32;
        let target_bits = (target as u32 & 0x1F) << 8;
        let token_bits = (token as u32 & 0x3) << 15;
        let error_bit = if expect_error { 1u32 << 17 } else { 0 };
        go | target_bits | token_bits | error_bit
    }

    fn calc_lc_state_mnemonic(state_5bit: u32) -> u32 {
        let s = state_5bit & 0x1F;
        (s << 25) | (s << 20) | (s << 15) | (s << 10) | (s << 5) | s
    }

    /// Run the LC transition test ROM with the given parameters.
    /// After the ROM reports success, performs a warm reset and verifies the
    /// new LC state from the host side.
    fn run_lc_transition_rom(
        from: LifecycleControllerState,
        target: LifecycleControllerState,
        token: TokenType,
        expect_error: bool,
    ) {
        let (caliptra_rom, mcu_rom) = load_roms();
        let wires0 = encode_wires(target, token, expect_error);

        let mut hw = caliptra_mcu_hw_model::new(InitParams {
            caliptra_rom: &caliptra_rom,
            mcu_rom: &mcu_rom,
            check_booted_to_runtime: false,
            enable_mcu_uart_log: true,
            lifecycle_controller_state: Some(from),
            rma_or_scrap_ppd: true,
            ..Default::default()
        })
        .unwrap();
        hw.set_mcu_generic_input_wires(&[wires0, 0xc000_0000]);

        hw.output().set_search_term("PASS");
        let start = std::time::Instant::now();
        hw.step_until(|m| {
            m.output().search_matched()
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 60
        });
        let output_text = hw.output().take(usize::MAX);
        println!("Test output:\n{output_text}");
        assert!(start.elapsed().as_secs() <= 60, "Test timed out");
        assert_eq!(hw.mci_fw_fatal_error(), None, "Test ROM hit fatal error");
        assert!(
            output_text.contains("PASS"),
            "Test ROM did not print PASS (from={from:?} target={target:?})"
        );

        // After transition, verify the new state via warm reset from host.
        if !expect_error {
            // Before warm reset: state should be PostTransition.
            let state = hw.mcu_manager().lc_ctrl().lc_state().read().state();
            assert_eq!(
                state,
                calc_lc_state_mnemonic(LifecycleControllerState::PostTransition as u32),
                "Expected PostTransition before warm reset (from={from:?} target={target:?})"
            );

            // Clear go-bit so the test ROM doesn't attempt another transition
            // after the warm reset re-boots it.
            hw.set_mcu_generic_input_wires(&[0, 0xc000_0000]);
            hw.warm_reset();

            // After warm reset: state should be the target.
            let state = hw.mcu_manager().lc_ctrl().lc_state().read().state();
            assert_eq!(
                state,
                calc_lc_state_mnemonic(target as u32),
                "Expected {target:?} after warm reset (from={from:?})"
            );
        }
    }

    use LifecycleControllerState::*;

    // ---- Individual transition tests ----

    #[test]
    fn test_lc_raw_to_test_unlocked0() {
        run_lc_transition_rom(Raw, TestUnlocked0, TokenType::RawUnlock, false);
    }

    #[test]
    fn test_lc_test_unlocked0_to_test_locked0() {
        run_lc_transition_rom(TestUnlocked0, TestLocked0, TokenType::None, false);
    }

    #[test]
    fn test_lc_test_locked0_to_test_unlocked1() {
        run_lc_transition_rom(TestLocked0, TestUnlocked1, TokenType::Default, false);
    }

    #[test]
    fn test_lc_test_unlocked7_to_dev() {
        run_lc_transition_rom(TestUnlocked7, Dev, TokenType::Default, false);
    }

    #[test]
    fn test_lc_dev_to_prod() {
        run_lc_transition_rom(Dev, Prod, TokenType::Default, false);
    }

    #[test]
    fn test_lc_dev_to_rma() {
        run_lc_transition_rom(Dev, Rma, TokenType::Default, false);
    }

    #[test]
    fn test_lc_prod_to_prod_end() {
        run_lc_transition_rom(Prod, ProdEnd, TokenType::Default, false);
    }

    #[test]
    fn test_lc_dev_to_scrap() {
        run_lc_transition_rom(Dev, Scrap, TokenType::None, false);
    }

    #[test]
    fn test_lc_prod_to_rma() {
        run_lc_transition_rom(Prod, Rma, TokenType::Default, false);
    }

    #[test]
    fn test_lc_prod_to_scrap() {
        run_lc_transition_rom(Prod, Scrap, TokenType::None, false);
    }

    #[test]
    fn test_lc_prod_end_to_scrap() {
        run_lc_transition_rom(ProdEnd, Scrap, TokenType::None, false);
    }

    #[test]
    fn test_lc_rma_to_scrap() {
        run_lc_transition_rom(Rma, Scrap, TokenType::None, false);
    }

    #[test]
    fn test_lc_raw_to_scrap() {
        run_lc_transition_rom(Raw, Scrap, TokenType::None, false);
    }

    #[test]
    fn test_lc_test_unlocked0_to_scrap() {
        run_lc_transition_rom(TestUnlocked0, Scrap, TokenType::None, false);
    }

    #[test]
    fn test_lc_test_locked0_to_scrap() {
        run_lc_transition_rom(TestLocked0, Scrap, TokenType::None, false);
    }

    // ---- Error tests ----

    #[test]
    fn test_lc_invalid_transition_error() {
        run_lc_transition_rom(Dev, Raw, TokenType::None, true);
    }

    #[test]
    fn test_lc_wrong_token_error() {
        run_lc_transition_rom(Raw, TestUnlocked0, TokenType::Default, true);
    }

    // Scrap state disables all CPU execution on real hardware, so the
    // test ROM cannot run. This is emulator-only.
    #[cfg_attr(feature = "fpga_realtime", ignore)]
    #[test]
    fn test_lc_scrap_is_terminal() {
        run_lc_transition_rom(Scrap, Raw, TokenType::None, true);
    }
}
