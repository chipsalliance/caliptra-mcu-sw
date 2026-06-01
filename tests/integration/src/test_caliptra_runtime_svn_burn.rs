// Licensed under the Apache-2.0 license

//! Cold-boot tests for MCU ROM's FW_INFO-driven `CPTRA_CORE_RUNTIME_SVN` burn.

#[cfg(test)]
mod test {
    use crate::test::{compile_runtime, start_runtime_hw_model, CustomCaliptraFw, TestParams};
    use anyhow::Result;
    use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, FirmwareBinaries};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_registers_generated::fuses::{
        FuseEntryInfo, OTP_CPTRA_CORE_ANTI_ROLLBACK_DISABLE, OTP_CPTRA_CORE_RUNTIME_SVN,
    };
    use caliptra_mcu_romtime::McuBootMilestones;

    /// Decode `CPTRA_CORE_RUNTIME_SVN` (linear-OR over 128 bits).
    fn runtime_svn_from_otp(otp: &[u8]) -> u32 {
        const SIZE: usize = OTP_CPTRA_CORE_RUNTIME_SVN.byte_size;
        let off = OTP_CPTRA_CORE_RUNTIME_SVN.byte_offset;
        let mut bytes = [0u8; SIZE];
        bytes.copy_from_slice(&otp[off..off + SIZE]);
        128 - u128::from_le_bytes(bytes).leading_zeros()
    }

    fn set_single_fuse(otp: &mut Vec<u8>, entry: &FuseEntryInfo, value: u32) {
        let end = entry.byte_offset + entry.byte_size;
        if otp.len() < end {
            otp.resize(end, 0);
        }
        otp[entry.byte_offset..entry.byte_offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn load_caliptra_fw_svn7() -> Result<(Vec<u8>, [u8; 48], Vec<u8>)> {
        let mcu_runtime_path = compile_runtime(Some("test-mcu-mbox-cmds"), false);
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            let fw = binaries.caliptra_fw_svn7.clone();
            let pk_hash = binaries.vendor_pk_hash().unwrap();
            let manifest = binaries.test_soc_manifest("test-mcu-mbox-cmds").unwrap();
            return Ok((fw, pk_hash, manifest));
        }
        let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
            svn: Some(7),
            mcu_firmware: Some(mcu_runtime_path),
            ..Default::default()
        });
        let fw = std::fs::read(builder.get_caliptra_fw()?).unwrap();
        let pk_hash_str = builder.get_vendor_pk_hash()?.to_string();
        let pk_hash = hex::decode(&pk_hash_str).unwrap();
        let mut pk_hash_arr = [0u8; 48];
        pk_hash_arr.copy_from_slice(&pk_hash);
        let manifest = std::fs::read(builder.get_soc_manifest(None)?).unwrap();
        Ok((fw, pk_hash_arr, manifest))
    }

    #[test]
    fn test_cold_boot_burns_caliptra_runtime_svn() -> Result<()> {
        let (fw_svn7, vendor_pk_hash, soc_manifest) = load_caliptra_fw_svn7()?;
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-mcu-mbox-cmds"),
            custom_caliptra_fw: Some(CustomCaliptraFw {
                fw_bytes: fw_svn7.clone(),
                vendor_pk_hash,
                soc_manifest: soc_manifest.clone(),
            }),
            ..Default::default()
        });

        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        });

        let otp_after_first_boot = hw.read_otp_memory();
        let burned = runtime_svn_from_otp(&otp_after_first_boot);
        assert!(
            burned >= 7,
            "CPTRA_CORE_RUNTIME_SVN not advanced: {}",
            burned
        );

        // Reboot with the same firmware and the OTP from the first
        // boot. The burn is idempotent: ROM must not error out trying
        // to re-burn an already-burned floor, the boot must reach the
        // mailbox-ready milestone, and the OTP value must be unchanged.
        // This is the same code path FwHitlessUpdate runs after Caliptra's
        // update_reset (where FW_INFO.min_fw_svn is typically <=
        // current_fuse so the burn is a no-op).
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-mcu-mbox-cmds"),
            custom_caliptra_fw: Some(CustomCaliptraFw {
                fw_bytes: fw_svn7,
                vendor_pk_hash,
                soc_manifest,
            }),
            otp_memory: Some(otp_after_first_boot.clone()),
            ..Default::default()
        });

        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        });

        let otp_after_second_boot = hw.read_otp_memory();
        assert_eq!(
            runtime_svn_from_otp(&otp_after_second_boot),
            runtime_svn_from_otp(&otp_after_first_boot),
            "second boot should not change the burned floor"
        );
        Ok(())
    }

    #[test]
    fn test_cold_boot_skips_burn_when_anti_rollback_disabled() -> Result<()> {
        let (fw_svn7, vendor_pk_hash, soc_manifest) = load_caliptra_fw_svn7()?;

        let mut otp = Vec::new();
        set_single_fuse(&mut otp, OTP_CPTRA_CORE_ANTI_ROLLBACK_DISABLE, 1);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-mcu-mbox-cmds"),
            custom_caliptra_fw: Some(CustomCaliptraFw {
                fw_bytes: fw_svn7,
                vendor_pk_hash,
                soc_manifest,
            }),
            otp_memory: Some(otp),
            ..Default::default()
        });

        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        });

        let burned = runtime_svn_from_otp(&hw.read_otp_memory());
        assert_eq!(burned, 0, "expected no burn, read {}", burned);
        Ok(())
    }
}
