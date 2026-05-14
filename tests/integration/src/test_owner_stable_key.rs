//! Licensed under the Apache-2.0 license

//! Tests for stable owner key derivation via CM_DERIVE_STABLE_KEY(OwnerKey).

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::McuHwModel;
    use registers_generated::fuses;
    use romtime::McuRomBootStatus;

    /// Test that stable owner key derivation succeeds during cold boot.
    #[test]
    fn test_stable_owner_key_derivation() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        println!("[TEST] Starting stable owner key derivation test");
        let seed_offset = fuses::STABLE_OWNER_KEY_PERSONALIZATION_SEED.byte_offset;
        let seed_size = fuses::STABLE_OWNER_KEY_PERSONALIZATION_SEED.byte_size;
        let mut otp = vec![0u8; seed_offset + seed_size];
        for (idx, byte) in otp[seed_offset..][..seed_size].iter_mut().enumerate() {
            *byte = (idx as u8) + 1;
        }

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: true,
            rom_feature: Some("stable-owner-key"),
            ..Default::default()
        });

        // Wait until cold boot moves past the stable owner key derivation path or hits a fatal error.
        hw.step_until(|m| {
            let checkpoint = (m.mci_flow_status() & 0xffff) as u16;
            checkpoint >= McuRomBootStatus::RiDownloadFirmwareCommandSent.into()
                || m.mci_fw_fatal_error().is_some()
        });

        // Verify no fatal error
        let fatal = hw.mci_fw_fatal_error();
        assert!(
            fatal.is_none() || fatal == Some(0),
            "ROM reported fatal error during stable owner key derivation: {:?}",
            fatal
        );

        // Verify the boot status moved past the derivation path.
        let checkpoint = (hw.mci_flow_status() & 0xffff) as u16;
        assert!(
            checkpoint >= McuRomBootStatus::RiDownloadFirmwareCommandSent.into(),
            "Expected boot to continue past stable owner key derivation, got checkpoint: {}",
            checkpoint
        );

        println!("[TEST] Stable owner key derivation path succeeded");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
