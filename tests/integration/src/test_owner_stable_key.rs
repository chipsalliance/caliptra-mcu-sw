//! Licensed under the Apache-2.0 license

//! Tests for HEK-based owner stable key derivation via CM_DERIVE_STABLE_KEY(OwnerKey).

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::McuHwModel;
    use romtime::McuRomBootStatus;

    /// Test that the HEK owner key derivation path is non-fatal during cold boot.
    ///
    /// TODO: Require HekOwnerKeyDerivationComplete once caliptra-sw has
    /// CmStableKeyType::OwnerKey support and the command is made fatal.
    #[test]
    fn test_hek_owner_key_derivation() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        println!("[TEST] Starting HEK owner key derivation test");
        let mut hw = start_runtime_hw_model(TestParams {
            rom_only: true,
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

        // Verify the boot status moved past the non-fatal derivation path.
        let checkpoint = (hw.mci_flow_status() & 0xffff) as u16;
        assert!(
            checkpoint >= McuRomBootStatus::RiDownloadFirmwareCommandSent.into(),
            "Expected boot to continue past HEK owner key derivation, got checkpoint: {}",
            checkpoint
        );

        // Step a bit more to flush remaining UART output for debugging
        hw.step_until(|m| m.cycle_count() > 20_000_000);

        println!("[TEST] HEK owner key derivation path remained non-fatal");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
