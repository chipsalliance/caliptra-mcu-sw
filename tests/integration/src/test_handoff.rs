// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use crate::test_hek::test::setup_otp_hek;
    use caliptra_mcu_hw_model::McuHwModel;

    #[test]
    fn test_handoff_integrity() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut otp = vec![0u8; 4096];
        // Program a valid HEK in slot 2 to verify dynamic state passing
        setup_otp_hek(&mut otp, 2, false, false);

        let mut hw = start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: false,
            ocp_lock_en: true,
            feature: Some("test-handoff"),
            rom_feature: Some("ocp-lock"),
            ..Default::default()
        });

        // A firmware exit ends the emulator test process, so check the boot log first.
        hw.step_until(|m| m.output().peek().contains("Executing test-handoff"));
        assert!(hw.output().peek().contains(
            "[mcu-runtime] HEK state from handoff: active_state=Programmed, active_slot=2, total_slots=8"
        ));
        hw.step_until_exit_success()
            .expect("HandOff verification failed in runtime");
    }

    /// A release runtime must read the handoff table that ROM wrote (#2196). The MCU ROM
    /// capabilities in MC_DEVICE_CAPABILITIES come from the kernel's `HandoffData::get()`.
    #[cfg(not(feature = "fpga_realtime"))]
    #[test]
    fn test_handoff_release_rom_caps() {
        use caliptra_mcu_mbox_common::messages::DeviceCapsReq;
        use caliptra_mcu_romtime::handoff::McuRomCapabilities;
        use caliptra_mcu_romtime::McuBootMilestones;

        let _lock = TEST_LOCK.lock().unwrap();
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("mcu-mbox-service"),
            profile: Some("release"),
            ..Default::default()
        });
        hw.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        });

        let resp = hw
            .mailbox_execute_req(DeviceCapsReq::default())
            .expect("MC_DEVICE_CAPABILITIES failed");
        let rom_caps = u32::from_be_bytes(resp.caps[16..20].try_into().unwrap());
        assert!(
            McuRomCapabilities::from_bits_retain(rom_caps)
                .contains(McuRomCapabilities::STREAMING_BOOT_I3C),
            "release runtime did not read the ROM handoff table (MCU ROM capabilities {rom_caps:#x})"
        );
    }
}
