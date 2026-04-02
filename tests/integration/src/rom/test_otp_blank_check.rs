// Licensed under the Apache-2.0 license

//! Integration test for OTP blank-check enforcement.
//!
//! Boots the `otp_blank_check` test ROM which writes 0x0F then 0x01 to the
//! same vendor_test_partition word. The second write must fail because it
//! would clear already-set bits. The ROM prints "PASS" if blank-check
//! behaves correctly.

#[cfg(test)]
mod test {
    use crate::platform;
    use mcu_builder::firmware;
    use mcu_hw_model::{InitParams, McuHwModel};
    use mcu_rom_common::LifecycleControllerState;

    fn load_roms() -> (Vec<u8>, Vec<u8>) {
        if let Ok(binaries) = mcu_builder::FirmwareBinaries::from_env() {
            (
                binaries.caliptra_rom.clone(),
                binaries
                    .test_rom(&firmware::hw_model_tests::OTP_BLANK_CHECK)
                    .unwrap(),
            )
        } else {
            let rom_file = mcu_builder::test_rom_build(&mcu_builder::CaliptraBuildArgs {
                platform: Some(platform()),
                fwid: Some(&firmware::hw_model_tests::OTP_BLANK_CHECK),
                ..Default::default()
            })
            .unwrap();
            (vec![], std::fs::read(&rom_file).unwrap())
        }
    }

    #[test]
    fn test_otp_blank_check() {
        let (caliptra_rom, mcu_rom) = load_roms();

        let mut hw = mcu_hw_model::new(InitParams {
            caliptra_rom: &caliptra_rom,
            mcu_rom: &mcu_rom,
            check_booted_to_runtime: false,
            enable_mcu_uart_log: true,
            lifecycle_controller_state: Some(LifecycleControllerState::Dev),
            ..Default::default()
        })
        .unwrap();
        hw.set_mcu_generic_input_wires(&[1, 0xc000_0000]);

        hw.output().set_search_term("PASS");
        let start = std::time::Instant::now();
        hw.step_until(|m| {
            m.output().search_matched()
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 30
        });
        let output_text = hw.output().take(usize::MAX);
        println!("Test output:\n{output_text}");
        assert!(start.elapsed().as_secs() <= 30, "Test timed out");
        assert_eq!(hw.mci_fw_fatal_error(), None, "Test ROM hit fatal error");
        assert!(output_text.contains("PASS"), "Test ROM did not print PASS");
    }
}
