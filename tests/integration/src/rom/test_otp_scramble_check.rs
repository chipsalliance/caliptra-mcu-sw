// Licensed under the Apache-2.0 license

//! Integration test verifying OTP PRESENT scrambling consistency.
//!
//! Boots the otp-scramble-check test ROM which reads the first dword of
//! vendor_secret_prod_partition via DAI (descrambles it), and prints the
//! result to UART. The host reads back the raw OTP SRAM via
//! read_otp_memory(), computes the expected descrambled value using the
//! Rust PRESENT implementation, and asserts both match.
//!
//! On emulator: verifies round-trip consistency of our PRESENT.
//! On FPGA: verifies our Rust PRESENT matches the RTL hardware PRESENT.

#[cfg(test)]
mod test {
    use crate::platform;
    use mcu_builder::firmware;
    use mcu_hw_model::{InitParams, McuHwModel};
    use mcu_rom_common::LifecycleControllerState;
    use registers_generated::fuses;

    fn load_roms() -> (Vec<u8>, Vec<u8>) {
        if let Ok(binaries) = mcu_builder::FirmwareBinaries::from_env() {
            (
                binaries.caliptra_rom.clone(),
                binaries
                    .test_rom(&firmware::hw_model_tests::OTP_SCRAMBLE_CHECK)
                    .unwrap(),
            )
        } else {
            let rom_file = mcu_builder::test_rom_build(&mcu_builder::CaliptraBuildArgs {
                platform: Some(platform()),
                fwid: Some(&firmware::hw_model_tests::OTP_SCRAMBLE_CHECK),
                ..Default::default()
            })
            .unwrap();
            (vec![], std::fs::read(&rom_file).unwrap())
        }
    }

    /// Parse a hex u32 from a UART line of the form "[...] KEY=ABCD1234".
    fn parse_hex_field(output: &str, key: &str) -> u32 {
        let line = output
            .lines()
            .find(|l| l.contains(key))
            .unwrap_or_else(|| panic!("Missing {} in UART output", key));
        let hex_str = line.split(key).nth(1).unwrap().trim();
        u32::from_str_radix(hex_str, 16)
            .unwrap_or_else(|e| panic!("Bad hex after {}: {:?} ({})", key, hex_str, e))
    }

    #[test]
    fn test_otp_scramble_check() {
        let (caliptra_rom, mcu_rom) = load_roms();
        let partition = fuses::VENDOR_SECRET_PROD_PARTITION;

        // Seed known raw bytes so the partition is non-zero.
        let seed_value: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        let last = fuses::OTP_PARTITIONS.last().unwrap();
        let otp_size = last.byte_offset + last.byte_size;
        let mut otp_data = vec![0u8; otp_size];
        otp_data[partition.byte_offset..partition.byte_offset + 8]
            .copy_from_slice(&seed_value.to_le_bytes());

        let mut hw = mcu_hw_model::new(InitParams {
            caliptra_rom: &caliptra_rom,
            mcu_rom: &mcu_rom,
            otp_memory: Some(&otp_data),
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
                || start.elapsed().as_secs() > 60
        });

        let output_text = hw.output().take(usize::MAX);
        println!("Test output:\n{output_text}");
        assert!(start.elapsed().as_secs() <= 60, "Test timed out");
        assert_eq!(hw.mci_fw_fatal_error(), None, "Test ROM hit fatal error");
        assert!(output_text.contains("PASS"), "Test ROM did not print PASS");

        // Parse the descrambled value from UART output.
        let lo = parse_hex_field(&output_text, "DESCRAMBLED_LO=");
        let hi = parse_hex_field(&output_text, "DESCRAMBLED_HI=");
        let dai_value = (lo as u64) | ((hi as u64) << 32);

        // Read back the actual raw OTP SRAM contents. On emulator this is
        // our seeded value; on FPGA it is whatever init_otp() provisioned.
        let otp_mem = hw.read_otp_memory();
        assert!(
            otp_mem.len() >= partition.byte_offset + 8,
            "OTP memory too small to contain partition data"
        );
        let raw_value = u64::from_le_bytes(
            otp_mem[partition.byte_offset..partition.byte_offset + 8]
                .try_into()
                .unwrap(),
        );

        // Compute expected descrambled value using our Rust PRESENT.
        let key = otp_digest::OTP_SCRAMBLE_KEYS[5];
        let expected = otp_digest::otp_unscramble(raw_value, key);

        assert_eq!(
            dai_value, expected,
            "DAI descrambled value does not match Rust PRESENT.\n\
             Raw SRAM:      {:#018x}\n\
             DAI returned:  {:#018x}\n\
             Rust expected: {:#018x}",
            raw_value, dai_value, expected
        );
    }
}
