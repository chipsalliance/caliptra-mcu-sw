// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use anyhow::Result;
    use mcu_error::McuError;
    use mcu_hw_model::{new, DefaultHwModel, InitParams, McuHwModel};
    use registers_generated::fuses;
    use romtime::{
        pqc_key_type_entry, vendor_ecc_revocation_entry, vendor_lms_revocation_entry,
        vendor_mldsa_revocation_entry, write_fuse_value, write_single_fuse_value, FuseLayout,
        PqcKeyType,
    };

    #[derive(Default, Clone, Copy)]
    struct SlotConfig {
        pqc_type: Option<PqcKeyType>,
        ecc_revocation: u32,
        lms_revocation: u32,
        mldsa_revocation: u32,
    }

    fn build_otp_memory(valid_mask: u16, slot_configs: &[(usize, SlotConfig)]) -> Vec<u8> {
        let otp_size = fuses::LIFE_CYCLE_BYTE_OFFSET + fuses::LIFE_CYCLE_BYTE_SIZE;
        let mut otp = vec![0u8; otp_size];

        // 1. Populate VENDOR_PK_HASH_VALID (LinearMajorityVote { bits: 16, duplication: 8 })
        let valid_entry = fuses::OTP_CPTRA_CORE_VENDOR_PK_HASH_VALID;
        let layout = FuseLayout::from_generated(&valid_entry.layout).unwrap();
        let raw_valid: [u32; 4] = write_fuse_value::<1, 4>(layout, &[valid_mask as u32]).unwrap();
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

            // 3. Populate Revocations (OneHotLinearMajorityVote)
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

    fn setup_hw_model(
        valid_mask: u16,
        slot_configs: &[(usize, SlotConfig)],
    ) -> Result<DefaultHwModel> {
        let binaries = mcu_builder::FirmwareBinaries::from_env()?;
        let otp_memory = build_otp_memory(valid_mask, slot_configs);

        new(InitParams {
            caliptra_rom: &binaries.caliptra_rom,
            mcu_rom: &binaries.mcu_rom,
            otp_memory: Some(&otp_memory),
            check_booted_to_runtime: false,
            enable_mcu_uart_log: true,
            ..Default::default()
        })
    }

    #[test]
    fn test_select_first_functional() -> Result<()> {
        let mut hw = setup_hw_model(
            0x0000,
            &[(
                0,
                SlotConfig {
                    pqc_type: Some(PqcKeyType::MLDSA),
                    ..SlotConfig::default()
                },
            )],
        )?;
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
                        pqc_type: Some(PqcKeyType::MLDSA),
                        ecc_revocation: 0b1111,
                        ..SlotConfig::default()
                    },
                ),
                (
                    1,
                    SlotConfig {
                        pqc_type: Some(PqcKeyType::MLDSA),
                        ..SlotConfig::default()
                    },
                ),
            ],
        )?;
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
                        pqc_type: Some(PqcKeyType::MLDSA),
                        mldsa_revocation: 0b1_1111,
                        ..SlotConfig::default()
                    },
                ),
                (
                    1,
                    SlotConfig {
                        pqc_type: Some(PqcKeyType::MLDSA),
                        ..SlotConfig::default()
                    },
                ),
            ],
        )?;
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
        )?;
        hw.step_until_output_contains("[mcu-fuse-write] Selected vendor PK slot 0")?;
        Ok(())
    }

    #[test]
    fn test_middle_slot_selection() -> Result<()> {
        let mut hw = setup_hw_model(
            0x00FF,
            &[(
                8,
                SlotConfig {
                    pqc_type: Some(PqcKeyType::MLDSA),
                    ..SlotConfig::default()
                },
            )],
        )?;
        hw.step_until_output_contains("[mcu-fuse-write] Selected vendor PK slot 8")?;
        Ok(())
    }

    #[test]
    fn test_last_slot_selection() -> Result<()> {
        let mut hw = setup_hw_model(
            0x7FFF,
            &[(
                15,
                SlotConfig {
                    pqc_type: Some(PqcKeyType::MLDSA),
                    ..SlotConfig::default()
                },
            )],
        )?;
        hw.step_until_output_contains("[mcu-fuse-write] Selected vendor PK slot 15")?;
        Ok(())
    }

    #[test]
    fn test_all_invalid_fails() -> Result<()> {
        let mut hw = setup_hw_model(0xFFFF, &[])?;
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
                        pqc_type: Some(PqcKeyType::MLDSA),
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
        )?;
        hw.step_until(|hw| hw.mci_fw_fatal_error().is_some());
        let fatal_error = hw.mci_fw_fatal_error().unwrap();
        assert_eq!(
            fatal_error,
            u32::from(McuError::ROM_PK_HASH_SELECTION_FAILED)
        );
        Ok(())
    }
}
