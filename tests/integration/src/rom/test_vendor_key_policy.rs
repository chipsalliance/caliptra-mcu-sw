// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use anyhow::Result;

    use caliptra_mcu_error::McuError;
    use caliptra_mcu_hw_model::{DefaultHwModel, McuHwModel, McuManager};
    use caliptra_mcu_registers_generated::fuses;
    use caliptra_mcu_romtime::{
        pqc_key_type_entry, vendor_ecc_revocation_entry, vendor_lms_revocation_entry,
        vendor_mldsa_revocation_entry, write_fuse_value, write_single_fuse_value, FuseLayout,
        PqcKeyType,
    };

    use crate::test::{start_runtime_hw_model, TestParams};

    #[derive(Clone, Copy)]
    struct SlotConfig {
        pqc_type: Option<PqcKeyType>,
        ecc_revocation: u32,
        lms_revocation: u32,
        mldsa_revocation: u32,
    }

    impl Default for SlotConfig {
        fn default() -> Self {
            SlotConfig {
                pqc_type: Some(PqcKeyType::MLDSA),
                ecc_revocation: 0,
                lms_revocation: 0,
                mldsa_revocation: 0,
            }
        }
    }

    fn build_otp_memory(valid_mask: u16, slot_configs: &[(usize, SlotConfig)]) -> Vec<u8> {
        let otp_size = fuses::LIFE_CYCLE_BYTE_OFFSET + fuses::LIFE_CYCLE_BYTE_SIZE;
        let mut otp = vec![0u8; otp_size];

        // 1. Populate VENDOR_PK_HASH_VALID (LinearOr { bits: 16, duplication: 3 })
        let valid_entry = fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_VALID;
        let layout = FuseLayout::from_generated(&valid_entry.layout).unwrap();
        let raw_valid: [u32; 2] = write_fuse_value::<1, 2>(layout, &[valid_mask as u32]).unwrap();
        for (i, &word) in raw_valid.iter().enumerate() {
            otp[valid_entry.byte_offset + i * 4..valid_entry.byte_offset + (i + 1) * 4]
                .copy_from_slice(&word.to_le_bytes());
        }

        for &(slot, config) in slot_configs {
            // 2. Populate PQC_KEY_TYPE_N
            if let Some(pqc_type) = config.pqc_type {
                let pqc_entry = pqc_key_type_entry(slot).expect("Invalid PQC entry");
                let pqc_layout = FuseLayout::from_generated(&pqc_entry.layout).unwrap();
                let raw_pqc = write_single_fuse_value(pqc_layout, pqc_type as u32).unwrap();
                otp[pqc_entry.byte_offset..pqc_entry.byte_offset + 4]
                    .copy_from_slice(&raw_pqc.to_le_bytes());
            }

            // 3. Populate Revocations (LinearOr)
            let ecc_entry =
                vendor_ecc_revocation_entry(slot).expect("Invalid ECC Revocation entry");
            let ecc_layout = FuseLayout::from_generated(&ecc_entry.layout).unwrap();
            let raw_ecc = write_single_fuse_value(ecc_layout, config.ecc_revocation).unwrap();
            otp[ecc_entry.byte_offset..ecc_entry.byte_offset + 4]
                .copy_from_slice(&raw_ecc.to_le_bytes());

            let lms_entry =
                vendor_lms_revocation_entry(slot).expect("Invalid LMS Revocation entry");
            let lms_layout = FuseLayout::from_generated(&lms_entry.layout).unwrap();
            let raw_lms = write_single_fuse_value(lms_layout, config.lms_revocation).unwrap();
            otp[lms_entry.byte_offset..lms_entry.byte_offset + 4]
                .copy_from_slice(&raw_lms.to_le_bytes());

            let mldsa_entry =
                vendor_mldsa_revocation_entry(slot).expect("Invalid MLDSA Revocation entry");
            let mldsa_layout = FuseLayout::from_generated(&mldsa_entry.layout).unwrap();
            let raw_mldsa = write_single_fuse_value(mldsa_layout, config.mldsa_revocation).unwrap();
            otp[mldsa_entry.byte_offset..mldsa_entry.byte_offset + 4]
                .copy_from_slice(&raw_mldsa.to_le_bytes());
        }

        otp
    }

    fn setup_hw_model(valid_mask: u16, slot_configs: &[(usize, SlotConfig)]) -> DefaultHwModel {
        let otp_memory = build_otp_memory(valid_mask, slot_configs);

        start_runtime_hw_model(TestParams {
            otp_memory: Some(otp_memory),
            rom_only: true,
            vendor_pqc_type: None,
            ..Default::default()
        })
    }

    #[test]
    fn test_select_first_functional() -> Result<()> {
        let mut hw = setup_hw_model(0x0000, &[(0, SlotConfig::default())]);
        hw.step_until_output_contains("[mcu-fuse-write] Selected vendor PK slot 0")?;
        Ok(())
    }

    #[test]
    fn test_skip_revoked_ecc() -> Result<()> {
        let mut hw = setup_hw_model(
            0x0000,
            &[
                (
                    0,
                    SlotConfig {
                        ecc_revocation: 0b1111,
                        ..SlotConfig::default()
                    },
                ),
                (1, SlotConfig::default()),
            ],
        );
        hw.step_until_output_contains("[mcu-fuse-write] Selected vendor PK slot 1")?;
        Ok(())
    }

    #[test]
    fn test_skip_revoked_pqc() -> Result<()> {
        let mut hw = setup_hw_model(
            0x0000,
            &[
                (
                    0,
                    SlotConfig {
                        mldsa_revocation: 0b1111,
                        ..SlotConfig::default()
                    },
                ),
                (1, SlotConfig::default()),
            ],
        );
        hw.step_until_output_contains("[mcu-fuse-write] Selected vendor PK slot 1")?;
        Ok(())
    }

    #[test]
    fn test_lms_threshold() -> Result<()> {
        let mut hw = setup_hw_model(
            0x0000,
            &[(
                0,
                SlotConfig {
                    pqc_type: Some(PqcKeyType::LMS),
                    lms_revocation: 0b1_1111,
                    ..SlotConfig::default()
                },
            )],
        );
        hw.step_until_output_contains("[mcu-fuse-write] Selected vendor PK slot 0")?;
        Ok(())
    }

    #[test]
    fn test_middle_slot_selection() -> Result<()> {
        let mut hw = setup_hw_model(0x00FF, &[(8, SlotConfig::default())]);
        hw.step_until_output_contains("[mcu-fuse-write] Selected vendor PK slot 8")?;
        Ok(())
    }

    #[test]
    fn test_last_slot_selection() -> Result<()> {
        let mut hw = setup_hw_model(0x7FFF, &[(15, SlotConfig::default())]);
        hw.step_until_output_contains("[mcu-fuse-write] Selected vendor PK slot 15")?;
        Ok(())
    }

    #[test]
    fn test_all_invalid_fails() -> Result<()> {
        let mut hw = setup_hw_model(0xFFFF, &[]);
        hw.step_until(|hw| hw.mci_fw_fatal_error().is_some());
        let fatal_error = hw.mci_fw_fatal_error().unwrap();
        assert_eq!(
            fatal_error,
            u32::from(McuError::ROM_PK_HASH_SELECTION_FAILED)
        );
        Ok(())
    }

    #[test]
    fn test_all_revoked_fails() -> Result<()> {
        let mut hw = setup_hw_model(
            0xFFFC,
            &[
                (
                    0,
                    SlotConfig {
                        ecc_revocation: 0b1111,
                        ..SlotConfig::default()
                    },
                ),
                (
                    1,
                    SlotConfig {
                        pqc_type: Some(PqcKeyType::LMS),
                        lms_revocation: 0xFFFF,
                        ..SlotConfig::default()
                    },
                ),
            ],
        );
        hw.step_until(|hw| hw.mci_fw_fatal_error().is_some());
        let fatal_error = hw.mci_fw_fatal_error().unwrap();
        assert_eq!(
            fatal_error,
            u32::from(McuError::ROM_PK_HASH_SELECTION_FAILED)
        );
        Ok(())
    }

    /// Returns (MANUF_PK_HASH_VOLATILE_LOCK, VENDOR_PK_HASH_VOLATILE_LOCK).
    fn vendor_pk_locks(hw: &mut DefaultHwModel) -> (u32, u32) {
        #[cfg(hw_rev = "latest")]
        let manuf = hw
            .mcu_manager()
            .with_otp(|otp| otp.manuf_pk_hash_volatile_lock().read());
        #[cfg(not(hw_rev = "latest"))]
        let manuf = 0;
        let prod = hw
            .mcu_manager()
            .with_otp(|otp| otp.vendor_pk_hash_volatile_lock().read());
        (manuf, prod)
    }

    /// Waits for ROM to select `slot` and lock the vendor PK hashes, then
    /// returns the lock registers.
    fn wait_for_vendor_pk_lock(hw: &mut DefaultHwModel, slot: usize) -> (u32, u32) {
        // ROM locks after Caliptra runtime is ready. Poll the registers: on
        // FPGA, ROM-only boot can step past the log messages before returning.
        let start = hw.cycle_count();
        hw.step_until(|hw| {
            vendor_pk_locks(hw).1 != 0
                || hw.mci_fw_fatal_error().is_some()
                || hw.cycle_count() - start > 800_000_000
        });
        assert_eq!(hw.mci_fw_fatal_error(), None);
        let output = hw.output().peek();
        assert!(output.contains(&format!("[mcu-fuse-write] Selected vendor PK slot {slot}")));
        assert!(output.contains(&format!(
            "[mcu-fuse-write] Locking vendor PK hash slots from index {slot}"
        )));
        let locks = vendor_pk_locks(hw);

        // The 2.2 lock bits are sticky until reset.
        #[cfg(hw_rev = "latest")]
        {
            hw.mcu_manager().with_otp(|otp| {
                otp.manuf_pk_hash_volatile_lock().write(|_| 0);
                otp.vendor_pk_hash_volatile_lock().write(|_| 0);
            });
            assert_eq!(vendor_pk_locks(hw), locks);
        }
        locks
    }

    #[test]
    fn test_vendor_pk_lock_applied() -> Result<()> {
        let mut hw = setup_hw_model(
            0x0000,
            &[(
                0,
                SlotConfig {
                    pqc_type: Some(PqcKeyType::LMS),
                    ..SlotConfig::default()
                },
            )],
        );
        let locks = wait_for_vendor_pk_lock(&mut hw, 0);
        // Slot 0 and all production slots are locked.
        #[cfg(hw_rev = "latest")]
        assert_eq!(locks, (1, 0x7fff));
        #[cfg(not(hw_rev = "latest"))]
        assert_eq!(locks, (0, 1));
        Ok(())
    }

    #[test]
    fn test_vendor_pk_lock_applied_production_slot() -> Result<()> {
        // Mark slot 0 invalid and put the image's vendor key hash in slot 1.
        let mut otp = build_otp_memory(
            0x0001,
            &[(
                1,
                SlotConfig {
                    pqc_type: Some(PqcKeyType::LMS),
                    ..SlotConfig::default()
                },
            )],
        );
        let hash: [u8; 48] = match caliptra_mcu_builder::FirmwareBinaries::from_env() {
            Ok(binaries) => binaries.vendor_pk_hash().unwrap(),
            Err(_) => crate::test::build_test_binaries(&TestParams::default())
                .vendor_pk_hash_u8
                .try_into()
                .unwrap(),
        };
        let entry = fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_1;
        for (dst, src) in otp[entry.byte_offset..entry.byte_offset + 48]
            .chunks_exact_mut(4)
            .zip(hash.chunks_exact(4))
        {
            dst.copy_from_slice(&[src[3], src[2], src[1], src[0]]);
        }
        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: true,
            vendor_pqc_type: None,
            ..Default::default()
        });
        let locks = wait_for_vendor_pk_lock(&mut hw, 1);
        // Slot 1 and all higher slots are locked; slot 0 is not.
        #[cfg(hw_rev = "latest")]
        assert_eq!(locks, (0, 0x7fff));
        #[cfg(not(hw_rev = "latest"))]
        assert_eq!(locks, (0, 2));
        Ok(())
    }

    #[test]
    fn test_vendor_pk_lock_not_applied() -> Result<()> {
        let mut hw = setup_hw_model(
            0x0000,
            &[(
                0,
                SlotConfig {
                    pqc_type: Some(PqcKeyType::LMS),
                    ..SlotConfig::default()
                },
            )],
        );

        // Set input wire bit to not lock the pk hashes
        hw.set_mcu_generic_input_wires(&[0, 0x1]);

        // Wait for ROM to take the skip-lock path.
        const SKIPPED: &str = "[mcu-fuse-write] PK Hash provisioning mode detected";
        if !hw.output().peek().contains(SKIPPED) {
            hw.output().set_search_term(SKIPPED);
            let start = hw.cycle_count();
            hw.step_until(|hw| {
                hw.output().search_matched()
                    || hw.mci_fw_fatal_error().is_some()
                    || hw.cycle_count() - start > 800_000_000
            });
        }
        assert_eq!(hw.mci_fw_fatal_error(), None);
        assert!(hw.output().peek().contains(SKIPPED));
        assert_eq!(vendor_pk_locks(&mut hw), (0, 0));
        Ok(())
    }

    #[test]
    fn test_key_rotation_strap() -> Result<()> {
        let mut hw = setup_hw_model(
            0x0002,
            &[(0, SlotConfig::default()), (2, SlotConfig::default())],
        );
        // Set input wire bit to jump 1 PK hash slot
        hw.set_mcu_generic_input_wires(&[0, 0x2]);

        // Slot 0 is the first functional slot which we skip
        // Slot 1 is marked invalid
        // Slot 2 should be selected
        hw.step_until_output_contains("[mcu-fuse-write] Selected vendor PK slot 2")?;
        Ok(())
    }
}
