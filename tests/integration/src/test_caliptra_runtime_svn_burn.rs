// Licensed under the Apache-2.0 license

//! Integration tests for MCU ROM's header-driven Caliptra-owned SVN
//! burns (`CPTRA_CORE_RUNTIME_SVN` and `CPTRA_CORE_SOC_MANIFEST_SVN`),
//! driven by the MCU runtime SVN header and guarded by `FW_INFO`.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_error::McuError;
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_registers_generated::fuses::{
        FuseEntryInfo, OTP_CPTRA_CORE_RUNTIME_SVN, OTP_CPTRA_CORE_SOC_MANIFEST_SVN,
    };
    use caliptra_mcu_romtime::{
        McuBootMilestones, McuComponentSvnEntry, McuComponentSvnManifest,
        MCU_COMPONENT_SVN_MANIFEST_MAGIC, MCU_COMPONENT_SVN_MANIFEST_VERSION,
    };
    use zerocopy::IntoBytes;

    /// Build an SVN header carrying only the Caliptra-owned min-SVN
    /// floors.
    fn header_bytes(caliptra_runtime_min_svn: u8, soc_manifest_min_svn: u8) -> Vec<u8> {
        let m = McuComponentSvnManifest {
            magic: MCU_COMPONENT_SVN_MANIFEST_MAGIC,
            format_version: MCU_COMPONENT_SVN_MANIFEST_VERSION,
            current_svn: 0,
            min_svn: 0,
            caliptra_runtime_min_svn,
            soc_manifest_min_svn,
            reserved: [0; 6],
            entries: [McuComponentSvnEntry::default(); 126],
        };
        m.as_bytes().to_vec()
    }

    /// Decode a 128-bit linear-OR SVN fuse (trailing-1 count) from `otp`.
    fn linear_or_svn_from_otp(otp: &[u8], entry: &FuseEntryInfo) -> u32 {
        const SIZE: usize = 16;
        let off = entry.byte_offset;
        let mut bytes = [0u8; SIZE];
        bytes.copy_from_slice(&otp[off..off + SIZE]);
        128 - u128::from_le_bytes(bytes).leading_zeros()
    }

    /// A header requesting a `soc_manifest_min_svn` floor burns
    /// `CPTRA_CORE_SOC_MANIFEST_SVN`. This path is guarded only by the
    /// header's self-attestation (FW_INFO has no SoC manifest SVN), so
    /// it does not query Caliptra.
    #[test]
    fn test_header_burns_soc_manifest_svn() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let header = header_bytes(0, 5);

        let mut hw = start_runtime_hw_model(TestParams {
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
            firmware_prefix: Some(header),
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
        assert!(
            linear_or_svn_from_otp(&otp, OTP_CPTRA_CORE_SOC_MANIFEST_SVN) >= 5,
            "CPTRA_CORE_SOC_MANIFEST_SVN not advanced: {}",
            linear_or_svn_from_otp(&otp, OTP_CPTRA_CORE_SOC_MANIFEST_SVN)
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// A header requesting a `caliptra_runtime_min_svn` floor burns
    /// `CPTRA_CORE_RUNTIME_SVN` after MCU ROM checks the floor against
    /// `FW_INFO.fw_svn`. Building Caliptra FW at SVN 7 makes the check
    /// pass (`fw_svn 7 >= floor 7`).
    #[test]
    fn test_header_burns_caliptra_runtime_svn() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let header = header_bytes(7, 0);

        let mut hw = start_runtime_hw_model(TestParams {
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
            firmware_prefix: Some(header),
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
        assert!(
            linear_or_svn_from_otp(&otp, OTP_CPTRA_CORE_RUNTIME_SVN) >= 7,
            "CPTRA_CORE_RUNTIME_SVN not advanced: {}",
            linear_or_svn_from_otp(&otp, OTP_CPTRA_CORE_RUNTIME_SVN)
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// When the header's `caliptra_runtime_min_svn` exceeds the running
    /// `FW_INFO.fw_svn`, MCU ROM rejects the boot rather than burning a
    /// floor the running firmware can't satisfy.
    #[test]
    fn test_header_caliptra_runtime_cross_check_rejected() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Caliptra FW is SVN 0 (default), but the header requests floor 1.
        let header = header_bytes(1, 0);

        let mut hw = start_runtime_hw_model(TestParams {
            target: &caliptra_mcu_builder::firmware::targets::TEST_SVN_MANIFEST,
            firmware_prefix: Some(header),
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

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
