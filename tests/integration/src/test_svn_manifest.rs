// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_error::McuError;
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_registers_generated::fuses::{
        FuseEntryInfo, MCU_COMPONENT_SVN_MANIFEST_MIN_SVN, SOC_IMAGE_MIN_SVN_0, SOC_IMAGE_MIN_SVN_1,
    };
    use caliptra_mcu_rom_common::{
        McuComponentSvnEntry, McuComponentSvnManifest, MCU_COMPONENT_SVN_MANIFEST_MAGIC,
        MCU_COMPONENT_SVN_MANIFEST_SIZE, MCU_COMPONENT_SVN_MANIFEST_VERSION,
    };
    use caliptra_mcu_romtime::{McuBootMilestones, McuRomBootStatus};
    use zerocopy::IntoBytes;

    const MANIFEST_MIN_SVN_FUSE: &FuseEntryInfo = MCU_COMPONENT_SVN_MANIFEST_MIN_SVN;

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
            caliptra_runtime_min_svn: 0,
            soc_manifest_min_svn: 0,
            reserved: [0; 6],
            entries: [McuComponentSvnEntry::default(); 126],
        };
        for (i, e) in entries {
            m.entries[*i] = *e;
        }
        m.as_bytes().to_vec()
    }

    /// Burn `value` (logical) into a OneHotLinearOr / dupe=3 fuse entry
    /// in an OTP image, growing the image as needed.
    fn set_fuse(otp: &mut Vec<u8>, entry: &FuseEntryInfo, value: u32) {
        let end = entry.byte_offset + entry.byte_size;
        if otp.len() < end {
            otp.resize(end, 0);
        }
        // OneHotLinearOr writes (value * dupe) consecutive bits starting
        // at bit 0 of the entry. dupe = 3 for all SVN fuses we use.
        let total_bits = (value * 3) as usize;
        for i in 0..total_bits {
            otp[entry.byte_offset + i / 8] |= 1 << (i % 8);
        }
    }

    /// Read the logical (decoded) value of a OneHotLinearOr / dupe=3
    /// fuse entry from `otp` (its effective range fits in one 32-bit
    /// word for all SVN fuses we use).
    fn fuse_value(otp: &[u8], entry: &FuseEntryInfo) -> u32 {
        let mut word_bytes = [0u8; 4];
        word_bytes.copy_from_slice(&otp[entry.byte_offset..entry.byte_offset + 4]);
        let mut raw = u32::from_le_bytes(word_bytes);
        let mut bits = 0u32;
        while raw & 1 != 0 {
            bits += 1;
            raw >>= 1;
        }
        bits / 3
    }

    /// Build an OTP image that pre-burns `value` into
    /// `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN`.
    fn otp_with_manifest_min_svn(value: u8) -> Vec<u8> {
        let mut otp = Vec::new();
        set_fuse(&mut otp, MANIFEST_MIN_SVN_FUSE, value.into());
        otp
    }

    fn manifest_min_svn_from_otp(otp: &[u8]) -> u32 {
        fuse_value(otp, MANIFEST_MIN_SVN_FUSE)
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
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
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
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
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
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
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
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
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
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
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
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
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

    /// Entries with `min_svn > 0` burn their mapped `SOC_IMAGE_MIN_SVN[i]`
    /// slots. component_id 0x1000 -> slot 0, 0x1002 -> slot 1 in the test
    /// ROM's SVN_FUSE_MAP.
    #[test]
    fn test_svn_manifest_burns_per_component_slot() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let manifest = manifest_bytes(
            1,
            0,
            &[
                (
                    0,
                    McuComponentSvnEntry {
                        component_id: 0x1000,
                        current_svn: 4,
                        min_svn: 3,
                    },
                ),
                (
                    1,
                    McuComponentSvnEntry {
                        component_id: 0x1002,
                        current_svn: 5,
                        min_svn: 5,
                    },
                ),
            ],
        );

        let mut hw = start_runtime_hw_model(TestParams {
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
            firmware_prefix: Some(manifest),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        assert_eq!(hw.mci_fw_fatal_error(), None, "unexpected fatal error");
        let otp = hw.read_otp_memory();
        assert!(
            fuse_value(&otp, SOC_IMAGE_MIN_SVN_0) >= 3,
            "SOC_IMAGE_MIN_SVN_0 not advanced: {}",
            fuse_value(&otp, SOC_IMAGE_MIN_SVN_0)
        );
        assert!(
            fuse_value(&otp, SOC_IMAGE_MIN_SVN_1) >= 5,
            "SOC_IMAGE_MIN_SVN_1 not advanced: {}",
            fuse_value(&otp, SOC_IMAGE_MIN_SVN_1)
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Two component_ids mapped to the same slot (0x1000 and 0x1001 ->
    /// slot 0) both advance it; the higher floor wins.
    #[test]
    fn test_svn_manifest_many_to_one_slot() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let manifest = manifest_bytes(
            1,
            0,
            &[
                (
                    0,
                    McuComponentSvnEntry {
                        component_id: 0x1000,
                        current_svn: 5,
                        min_svn: 2,
                    },
                ),
                (
                    1,
                    McuComponentSvnEntry {
                        component_id: 0x1001,
                        current_svn: 5,
                        min_svn: 5,
                    },
                ),
            ],
        );

        let mut hw = start_runtime_hw_model(TestParams {
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
            firmware_prefix: Some(manifest),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        assert_eq!(hw.mci_fw_fatal_error(), None, "unexpected fatal error");
        let otp = hw.read_otp_memory();
        assert!(
            fuse_value(&otp, SOC_IMAGE_MIN_SVN_0) >= 5,
            "shared slot not advanced to higher floor: {}",
            fuse_value(&otp, SOC_IMAGE_MIN_SVN_0)
        );
        assert_eq!(fuse_value(&otp, SOC_IMAGE_MIN_SVN_1), 0);

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// An entry whose `component_id` is not in SVN_FUSE_MAP is skipped
    /// (logged), boot completes, and no slot is burned.
    #[test]
    fn test_svn_manifest_unmapped_component_id_skipped() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let manifest = manifest_bytes(
            1,
            0,
            &[(
                0,
                McuComponentSvnEntry {
                    component_id: 0xdead_beef,
                    current_svn: 4,
                    min_svn: 3,
                },
            )],
        );

        let mut hw = start_runtime_hw_model(TestParams {
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
            firmware_prefix: Some(manifest),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        assert_eq!(hw.mci_fw_fatal_error(), None);
        let otp = hw.read_otp_memory();
        assert_eq!(fuse_value(&otp, SOC_IMAGE_MIN_SVN_0), 0);
        assert_eq!(fuse_value(&otp, SOC_IMAGE_MIN_SVN_1), 0);

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// A per-component entry rolled back relative to its slot
    /// (`current_svn` < fuse floor) halts the boot.
    #[test]
    fn test_svn_manifest_per_component_rolled_back_rejected() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Pre-burn slot 0 to 3, then claim component_id 0x1000 current_svn=2.
        let mut otp = otp_with_manifest_min_svn(0);
        set_fuse(&mut otp, SOC_IMAGE_MIN_SVN_0, 3);

        let manifest = manifest_bytes(
            1,
            0,
            &[(
                0,
                McuComponentSvnEntry {
                    component_id: 0x1000,
                    current_svn: 2,
                    min_svn: 0,
                },
            )],
        );

        let mut hw = start_runtime_hw_model(TestParams {
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
            firmware_prefix: Some(manifest),
            otp_memory: Some(otp),
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

    /// Regression test for the validate-before-burn invariant: a header
    /// that requests manifest-self and per-component burns but whose
    /// Caliptra-runtime cross-check fails (caliptra_runtime_min_svn=1 >
    /// FW_INFO.fw_svn=0) must reject the boot *without* committing any
    /// burn, so the device isn't left with partially-advanced floors.
    #[test]
    fn test_svn_manifest_no_burn_before_fatal() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut m = McuComponentSvnManifest {
            magic: MCU_COMPONENT_SVN_MANIFEST_MAGIC,
            format_version: MCU_COMPONENT_SVN_MANIFEST_VERSION,
            current_svn: 3,
            min_svn: 3,                  // would burn MCU_COMPONENT_SVN_MANIFEST_MIN_SVN
            caliptra_runtime_min_svn: 1, // fatals: > FW_INFO.fw_svn (0)
            soc_manifest_min_svn: 0,
            reserved: [0; 6],
            entries: [McuComponentSvnEntry::default(); 126],
        };
        m.entries[0] = McuComponentSvnEntry {
            component_id: 0x1000, // maps to SOC_IMAGE_MIN_SVN_0
            current_svn: 4,
            min_svn: 3, // would burn SOC_IMAGE_MIN_SVN_0
        };
        let manifest = m.as_bytes().to_vec();

        let mut hw = start_runtime_hw_model(TestParams {
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
            firmware_prefix: Some(manifest),
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() > 100_000_000);

        assert_eq!(
            hw.mci_fw_fatal_error(),
            Some(u32::from(McuError::ROM_CALIPTRA_RUNTIME_SVN_BURN_ERROR)),
            "expected ROM_CALIPTRA_RUNTIME_SVN_BURN_ERROR, got {:?}",
            hw.mci_fw_fatal_error()
        );

        // The fatal happened in the validation phase, so neither the
        // manifest-self nor the per-component floor should be burned.
        let otp = hw.read_otp_memory();
        assert_eq!(
            manifest_min_svn_from_otp(&otp),
            0,
            "MCU_COMPONENT_SVN_MANIFEST_MIN_SVN burned before fatal"
        );
        assert_eq!(
            fuse_value(&otp, SOC_IMAGE_MIN_SVN_0),
            0,
            "SOC_IMAGE_MIN_SVN_0 burned before fatal"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
