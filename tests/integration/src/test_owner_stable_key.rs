//! Licensed under the Apache-2.0 license

//! Tests for HEK-based owner stable key derivation via CM_DERIVE_STABLE_KEY(OwnerKey).

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::McuHwModel;
    use romtime::otp::{
        cptra_ss_vendor_specific_non_secret_fuse_offset,
        CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_SIZE,
    };
    use romtime::McuRomBootStatus;

    const STABLE_OWNER_KEY_PERSONALIZATION_SEED_FUSE_INDEX: usize = 0;
    const STABLE_OWNER_KEY_PERSONALIZATION_SEED_OFFSET: usize =
        cptra_ss_vendor_specific_non_secret_fuse_offset(
            STABLE_OWNER_KEY_PERSONALIZATION_SEED_FUSE_INDEX,
        );

    /// Test that the HEK owner key derivation path succeeds during cold boot.
    #[test]
    fn test_hek_owner_key_derivation() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        println!("[TEST] Starting HEK owner key derivation test");
        let mut otp = vec![
            0u8;
            STABLE_OWNER_KEY_PERSONALIZATION_SEED_OFFSET
                + CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_SIZE
        ];
        for (idx, byte) in otp[STABLE_OWNER_KEY_PERSONALIZATION_SEED_OFFSET..]
            [..CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_SIZE]
            .iter_mut()
            .enumerate()
        {
            *byte = (idx as u8) + 1;
        }

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: true,
            rom_feature: Some("stable-owner-key"),
            ..Default::default()
        });

        // Wait until cold boot moves past the owner key derivation path or hits a fatal error.
        hw.step_until(|m| {
            let checkpoint = (m.mci_flow_status() & 0xffff) as u16;
            checkpoint >= McuRomBootStatus::RiDownloadFirmwareCommandSent.into()
                || m.mci_fw_fatal_error().is_some()
        });

        // Verify no fatal error
        let fatal = hw.mci_fw_fatal_error();
        assert!(
            fatal.is_none() || fatal == Some(0),
            "ROM reported fatal error during HEK owner key derivation: {:?}",
            fatal
        );

        // Verify the boot status moved past the derivation path.
        let checkpoint = (hw.mci_flow_status() & 0xffff) as u16;
        assert!(
            checkpoint >= McuRomBootStatus::RiDownloadFirmwareCommandSent.into(),
            "Expected boot to continue past HEK owner key derivation, got checkpoint: {}",
            checkpoint
        );

        println!("[TEST] HEK owner key derivation path succeeded");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
