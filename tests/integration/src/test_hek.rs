// Licensed under the Apache-2.0 license

#[cfg(test)]
pub mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_api::SocManager;
    use mcu_hw_model::McuHwModel;
    use otp_digest;
    use registers_generated::fuses;
    use zerocopy::IntoBytes;

    pub fn setup_otp_hek(otp: &mut [u8], slot: usize, sanitized: bool, corrupted: bool) {
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
            if corrupted {
                otp[offset + 32] ^= 0x1; // Corrupt the digest
            }
        } else {
            for i in 0..32 {
                otp[offset + i] = (slot as u8 + 1) ^ (i as u8);
            }

            // Compute software digest
            let iv = 0x90C7F21F6224F027u64;
            let cnst = 0xF98C48B1F93772844A22D4B78FE0266Fu128;
            let blocks = (0..4).map(|i| {
                u64::from_le_bytes(otp[offset + i * 8..offset + i * 8 + 8].try_into().unwrap())
            });
            let mut digest = otp_digest::otp_digest_iter(blocks, iv, cnst);

            if corrupted {
                digest ^= 0x1;
            }

            otp[offset + 32..offset + 40].copy_from_slice(&digest.to_le_bytes());
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
        setup_otp_hek(&mut otp, 0, false, false);

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: true,
            ocp_lock_en: true,
            rom_feature: Some("ocp-lock"),
            ..Default::default()
        });

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
            setup_otp_hek(&mut otp, slot, true, false);
        }

        let active_slot = sanitized_slots.len();
        setup_otp_hek(&mut otp, active_slot, false, false);

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: true,
            ocp_lock_en: true,
            rom_feature: Some("ocp-lock"),
            ..Default::default()
        });

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

    #[test]
    fn test_hek_slot_selection_for_stable_owner_key() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut otp = vec![0u8; 4096];

        let sanitized_slots = [0, 1];
        for slot in sanitized_slots {
            setup_otp_hek(&mut otp, slot, true, false);
        }

        let active_slot = sanitized_slots.len();
        setup_otp_hek(&mut otp, active_slot, false, false);

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: true,
            rom_feature: Some("stable-owner-key"),
            ..Default::default()
        });

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

        let stable_owner_key_strap = hw
            .caliptra_soc_manager()
            .soc_ifc()
            .ss_strap_generic()
            .at(3)
            .read();
        assert_eq!(stable_owner_key_strap & 1, 1);
    }

    #[test]
    fn test_hek_available_from_report() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut otp = vec![0u8; 4096];
        // Program a valid HEK in slot 0
        setup_otp_hek(&mut otp, 0, false, false);

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: false,
            ocp_lock_en: true,
            feature: Some("test-ocp-lock"),
            rom_feature: Some("ocp-lock"),
            ..Default::default()
        });

        assert_eq!(0, finish_runtime_hw_model(&mut hw));
        assert!(hw
            .output()
            .peek()
            .contains("[mcu-rom] Caliptra HEK available: true"));
        assert!(hw
            .output()
            .peek()
            .contains("[mcu-runtime] HEK state from handoff"));
    }

    #[test]
    fn test_hek_available_from_perma_bit() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut otp = vec![0u8; 4096];
        set_hek_perma(&mut otp);

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: false,
            ocp_lock_en: true,
            feature: Some("test-ocp-lock"),
            rom_feature: Some("ocp-lock"),
            ..Default::default()
        });

        assert_eq!(0, finish_runtime_hw_model(&mut hw));
        assert!(hw
            .output()
            .peek()
            .contains("[mcu-rom] Caliptra HEK available: true"));
        assert!(hw
            .output()
            .peek()
            .contains("[mcu-runtime] HEK state from handoff"));
    }

    #[test]
    fn test_hek_unavailable() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut otp = vec![0u8; 4096];
        // Sanitize all HEK slots
        for slot in 0..8 {
            setup_otp_hek(&mut otp, slot, true, false);
        }

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: false,
            ocp_lock_en: true,
            feature: Some("test-ocp-lock"),
            rom_feature: Some("ocp-lock"),
            ..Default::default()
        });

        assert_eq!(0, finish_runtime_hw_model(&mut hw));
        assert!(hw
            .output()
            .peek()
            .contains("[mcu-rom] Caliptra HEK available: false"));
        assert!(hw
            .output()
            .peek()
            .contains("[mcu-runtime] HEK state from handoff"));
    }

    #[test]
    fn test_hek_digest_mismatch() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut otp = vec![0u8; 4096];
        // Program a corrupted HEK in slot 0
        setup_otp_hek(&mut otp, 0, false, true);

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: true,
            ocp_lock_en: true,
            rom_feature: Some("ocp-lock"),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.caliptra_soc_manager()
                .soc_ifc()
                .cptra_fuse_wr_done()
                .read()
                .done()
        });

        let hek_seed = hw.caliptra_soc_manager().soc_ifc().fuse_hek_seed().read();
        for i in 0..8 {
            assert_eq!(
                hek_seed[i], 0,
                "HEK seed should be zeroed on digest mismatch"
            );
        }
    }
}
