// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{get_rom_with_feature, TEST_LOCK};
    use caliptra_api::SocManager;
    use mcu_hw_model::{InitParams, McuHwModel};
    use registers_generated::fuses;
    use zerocopy::IntoBytes;

    fn setup_otp_hek(otp: &mut [u8], slot: usize, sanitized: bool) {
        let offset = [
            fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_1_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_2_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_3_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_4_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_5_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_6_BYTE_OFFSET,
            fuses::CPTRA_SS_LOCK_HEK_PROD_7_BYTE_OFFSET,
        ][slot];

        if sanitized {
            // Write 0xFF to the entire 48-byte partition (Seed, Digest, and ZER)
            for i in 0..48 {
                otp[offset + i] = 0xFF;
            }
        } else {
            for i in 0..32 {
                otp[offset + i] = (slot as u8 + 1) ^ (i as u8);
            }
        }
    }

    fn set_hek_perma(otp: &mut [u8]) {
        let offset = fuses::PERMA_HEK_EN.byte_offset;
        // For a 1-bit LinearMajorityVote with duplication 3, setting the bit to 1 means
        // setting all 3 physical bits to 1. Since the layout is word-sized, we write 0x1
        // into the appropriate word in the OTP memory.
        let word_offset = offset / 4;
        let byte_offset_start = word_offset * 4;
        let current_word = u32::from_le_bytes(
            otp[byte_offset_start..byte_offset_start + 4]
                .try_into()
                .unwrap(),
        );
        let new_word = current_word | 0x7; // Set all 3 physical bits for logical 1
        otp[byte_offset_start..byte_offset_start + 4].copy_from_slice(&new_word.to_le_bytes());
    }

    #[test]
    fn test_hek_perma_bit() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut otp = vec![0u8; 4096];
        set_hek_perma(&mut otp);
        setup_otp_hek(&mut otp, 0, false);

        let mut hw = mcu_hw_model::new(InitParams {
            mcu_rom: &std::fs::read(get_rom_with_feature("")).unwrap(),
            otp_memory: Some(&otp),
            check_booted_to_runtime: false,
            enable_mcu_uart_log: true,
            ..Default::default()
        })
        .unwrap();

        hw.step_until(|m| {
            m.caliptra_soc_manager()
                .soc_ifc()
                .cptra_fuse_wr_done()
                .read()
                .done()
        });

        let hek_seed = hw.caliptra_soc_manager().soc_ifc().fuse_hek_seed().read();
        for i in 0..8 {
            assert_eq!(hek_seed[i], 0xFFFF_FFFF);
        }
    }

    #[test]
    fn test_hek_slot_selection() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut otp = vec![0u8; 4096];

        let sanitized_slots = [0, 1];
        for slot in sanitized_slots {
            setup_otp_hek(&mut otp, slot, true);
        }

        let active_slot = sanitized_slots.len();
        setup_otp_hek(&mut otp, active_slot, false);

        let mut hw = mcu_hw_model::new(InitParams {
            mcu_rom: &std::fs::read(get_rom_with_feature("")).unwrap(),
            otp_memory: Some(&otp),
            check_booted_to_runtime: false,
            enable_mcu_uart_log: true,
            ..Default::default()
        })
        .unwrap();

        hw.step_until(|m| {
            m.caliptra_soc_manager()
                .soc_ifc()
                .cptra_fuse_wr_done()
                .read()
                .done()
        });

        let hek_seed = hw.caliptra_soc_manager().soc_ifc().fuse_hek_seed().read();
        for (idx, &byte) in hek_seed.as_bytes().iter().enumerate() {
            assert_eq!(byte, ((active_slot + 1) ^ idx) as u8);
        }
    }
}
