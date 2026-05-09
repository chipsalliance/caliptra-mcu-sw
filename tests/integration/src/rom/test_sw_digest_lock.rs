// Licensed under the Apache-2.0 license

//! Integration test for `Otp::write_sw_digest_and_lock`.
//!
//! Two cold boots:
//! 1. First boot writes data + digest to vendor_test_partition, prints "DONE".
//! 2. Second boot re-computes and verifies the digest, prints "PASS".

#[cfg(test)]
mod test {
    use crate::platform;
    use mcu_builder::firmware;
    use mcu_hw_model::{InitParams, McuHwModel};
    use registers_generated::fuses;
    use romtime::LifecycleControllerState;

    fn load_roms() -> (Vec<u8>, Vec<u8>) {
        if let Ok(binaries) = mcu_builder::FirmwareBinaries::from_env() {
            (
                binaries.caliptra_rom.clone(),
                binaries
                    .test_rom(&firmware::hw_model_tests::SW_DIGEST_LOCK)
                    .unwrap(),
            )
        } else {
            let rom_file = mcu_builder::test_rom_build(
                Some(platform()),
                &firmware::hw_model_tests::SW_DIGEST_LOCK,
            )
            .unwrap();
            (vec![], std::fs::read(&rom_file).unwrap())
        }
    }

    #[test]
    fn test_sw_digest_lock() {
        let (caliptra_rom, mcu_rom) = load_roms();

        // On FPGA, OTP SRAM persists across runs. Clear vendor_test_partition
        // before the real test. The go-bit prevents the ROM from racing.
        #[cfg(feature = "fpga_realtime")]
        {
            let tmp = mcu_hw_model::new_unbooted(InitParams {
                caliptra_rom: &caliptra_rom,
                mcu_rom: &mcu_rom,
                check_booted_to_runtime: false,
                lifecycle_controller_state: Some(LifecycleControllerState::Dev),
                ..Default::default()
            })
            .unwrap();
            let p = fuses::VENDOR_TEST_PARTITION;
            let mut copy = tmp.base.otp_slice().to_vec();
            copy[p.byte_offset..p.byte_offset + p.byte_size].fill(0);
            tmp.base.otp_slice().copy_from_slice(&copy);
            drop(tmp);
        }

        // Boot 1: write data + digest.
        let otp_after_boot1;
        {
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

            hw.output().set_search_term("DONE");
            let start = std::time::Instant::now();
            hw.step_until(|m| {
                m.output().search_matched()
                    || m.mci_fw_fatal_error().is_some()
                    || start.elapsed().as_secs() > 30
            });
            let output_text = hw.output().take(usize::MAX);
            println!("Boot 1 output:\n{output_text}");
            assert!(start.elapsed().as_secs() <= 30, "Boot 1 timed out");
            assert_eq!(hw.mci_fw_fatal_error(), None, "Boot 1 fatal error");

            // Capture OTP state for boot 2 (emulator doesn't persist OTP).
            otp_after_boot1 = hw.read_otp_memory();
        }

        // Boot 2: verify digest. Pass OTP from boot 1 so emulator sees the
        // written data. On FPGA, OTP SRAM persists automatically.
        {
            let mut hw = mcu_hw_model::new(InitParams {
                caliptra_rom: &caliptra_rom,
                mcu_rom: &mcu_rom,
                check_booted_to_runtime: false,
                enable_mcu_uart_log: true,
                lifecycle_controller_state: Some(LifecycleControllerState::Dev),
                otp_memory: Some(&otp_after_boot1),
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
            println!("Boot 2 output:\n{output_text}");
            assert!(start.elapsed().as_secs() <= 30, "Boot 2 timed out");
            assert_eq!(hw.mci_fw_fatal_error(), None, "Boot 2 fatal error");

            // Also verify digest via OTP memory readback.
            let final_otp = hw.read_otp_memory();
            let digest_offset = fuses::VENDOR_TEST_PARTITION
                .digest_offset
                .expect("vendor_test_partition should have a digest offset");
            let digest_lo = u32::from_le_bytes(
                final_otp[digest_offset..digest_offset + 4]
                    .try_into()
                    .unwrap(),
            );
            let digest_hi = u32::from_le_bytes(
                final_otp[digest_offset + 4..digest_offset + 8]
                    .try_into()
                    .unwrap(),
            );
            let digest = digest_lo as u64 | ((digest_hi as u64) << 32);
            assert_ne!(digest, 0, "Digest should have been written to OTP");
            println!("OTP digest verified: {digest:#018x}");
        }
    }
}
