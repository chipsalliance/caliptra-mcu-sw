// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_error::McuError;
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_registers_generated::fuses::OTP_CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_5;
    use caliptra_mcu_rom_common::{
        McuComponentSvnEntry, McuComponentSvnManifest, MCU_COMPONENT_SVN_MANIFEST_MAGIC,
        MCU_COMPONENT_SVN_MANIFEST_SIZE, MCU_COMPONENT_SVN_MANIFEST_VERSION,
    };
    use caliptra_mcu_romtime::{McuBootMilestones, McuRomBootStatus};
    use zerocopy::IntoBytes;

    fn manifest_bytes(
        current_svn: u8,
        min_svn: u8,
        entries: &[(usize, McuComponentSvnEntry)],
    ) -> Vec<u8> {
        let mut m = McuComponentSvnManifest {
            magic: MCU_COMPONENT_SVN_MANIFEST_MAGIC,
            format_version: MCU_COMPONENT_SVN_MANIFEST_VERSION,
            current_svn,
            min_svn,
            entries: [McuComponentSvnEntry::default(); 127],
        };
        for (i, e) in entries {
            m.entries[*i] = *e;
        }
        m.as_bytes().to_vec()
    }

    /// Build an OTP image that pre-burns `value` into
    /// `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN` (OneHotLinearOr / dupe=3).
    fn otp_with_manifest_min_svn(value: u8) -> Vec<u8> {
        let entry = OTP_CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_5;
        let end = entry.byte_offset + entry.byte_size;
        let mut otp = vec![0u8; end];
        // OneHotLinearOr writes (value * dupe) consecutive bits starting at
        // bit 0 of the entry. dupe = 3 for this fuse.
        let total_bits = value as usize * 3;
        for i in 0..total_bits {
            otp[entry.byte_offset + i / 8] |= 1 << (i % 8);
        }
        otp
    }

    /// Read the logical (decoded) value of `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN`
    /// from `otp`. The fuse uses OneHotLinearOr / dupe=3, so the logical
    /// value is `(consecutive_set_bits / 3)`.
    fn manifest_min_svn_from_otp(otp: &[u8]) -> u32 {
        let entry = OTP_CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_5;
        let mut bits = 0u32;
        // Read the 4-byte raw window we use; the fuse's effective range
        // fits in one 32-bit word.
        let mut word_bytes = [0u8; 4];
        word_bytes.copy_from_slice(&otp[entry.byte_offset..entry.byte_offset + 4]);
        let mut raw = u32::from_le_bytes(word_bytes);
        while raw & 1 != 0 {
            bits += 1;
            raw >>= 1;
        }
        bits / 3
    }

    /// A well-formed manifest passes validation and ROM skips past it,
    /// reaching the firmware-boot-flow-complete milestone.
    #[test]
    fn test_svn_manifest_valid_skipped() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let manifest = manifest_bytes(
            3,
            0,
            &[(
                0,
                McuComponentSvnEntry {
                    component_id: 0x1000,
                    current_svn: 5,
                    min_svn: 2,
                },
            )],
        );
        assert_eq!(manifest.len(), MCU_COMPONENT_SVN_MANIFEST_SIZE);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-svn-manifest"),
            firmware_prefix: Some(manifest),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        assert_eq!(
            hw.mci_fw_fatal_error(),
            None,
            "unexpected fatal error during boot"
        );
        assert!(
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE),
            "firmware boot did not complete (checkpoint = {})",
            hw.mci_boot_checkpoint()
        );
        assert!(
            hw.mci_boot_checkpoint()
                >= McuRomBootStatus::ComponentSvnManifestProcessingComplete.into(),
            "manifest processing did not complete (checkpoint = {})",
            hw.mci_boot_checkpoint()
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// If the bytes at the manifest's location don't carry the magic,
    /// the manifest is silently skipped and the boot proceeds as usual.
    /// (The runtime begins right at the existing firmware offset.)
    #[test]
    fn test_svn_manifest_magic_absent_skipped() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-svn-manifest"),
            // No firmware_prefix: the test ROM enables the manifest
            // path, but the first 4 bytes of the runtime are not the
            // SVN magic, so it's skipped.
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        assert_eq!(hw.mci_fw_fatal_error(), None);
        assert!(hw
            .mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE));

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// A manifest with `min_svn > current_svn` is rejected with
    /// `ROM_COMPONENT_SVN_MANIFEST_ERROR`.
    #[test]
    fn test_svn_manifest_invalid_header() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let manifest = manifest_bytes(2, 3, &[]);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-svn-manifest"),
            firmware_prefix: Some(manifest),
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() > 100_000_000);

        assert_eq!(
            hw.mci_fw_fatal_error(),
            Some(u32::from(McuError::ROM_COMPONENT_SVN_MANIFEST_ERROR)),
            "expected ROM_COMPONENT_SVN_MANIFEST_ERROR, got {:?}",
            hw.mci_fw_fatal_error()
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// `manifest.current_svn < MCU_COMPONENT_SVN_MANIFEST_MIN_SVN` halts
    /// boot with `ROM_COMPONENT_SVN_MANIFEST_ERROR`.
    #[test]
    fn test_svn_manifest_rolled_back_rejected() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Manifest declares current_svn = 1, but the fuse is at 3.
        let manifest = manifest_bytes(1, 0, &[]);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-svn-manifest"),
            firmware_prefix: Some(manifest),
            otp_memory: Some(otp_with_manifest_min_svn(3)),
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() > 100_000_000);

        assert_eq!(
            hw.mci_fw_fatal_error(),
            Some(u32::from(McuError::ROM_COMPONENT_SVN_MANIFEST_ERROR)),
            "expected ROM_COMPONENT_SVN_MANIFEST_ERROR, got {:?}",
            hw.mci_fw_fatal_error()
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// `manifest.current_svn == MCU_COMPONENT_SVN_MANIFEST_MIN_SVN` is
    /// accepted (boundary case).
    #[test]
    fn test_svn_manifest_at_fuse_boundary_accepted() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let manifest = manifest_bytes(3, 0, &[]);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-svn-manifest"),
            firmware_prefix: Some(manifest),
            otp_memory: Some(otp_with_manifest_min_svn(3)),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        assert_eq!(hw.mci_fw_fatal_error(), None);
        assert!(hw
            .mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE));

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// `manifest.min_svn > fuse_min_svn` triggers a burn; readback shows
    /// the new floor.
    #[test]
    fn test_svn_manifest_burn_min_svn() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Fuse starts at 1; manifest requests floor of 4. Boot should
        // succeed (current_svn 5 >= fuse 1) and ROM should burn 1 -> 4.
        let manifest = manifest_bytes(5, 4, &[]);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-svn-manifest"),
            firmware_prefix: Some(manifest),
            otp_memory: Some(otp_with_manifest_min_svn(1)),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        assert_eq!(hw.mci_fw_fatal_error(), None, "unexpected fatal error");
        assert!(hw
            .mci_boot_milestones()
            .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE));

        let otp = hw.read_otp_memory();
        let burned = manifest_min_svn_from_otp(&otp);
        assert!(
            burned >= 4,
            "MCU_COMPONENT_SVN_MANIFEST_MIN_SVN was not advanced: read {}",
            burned
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
