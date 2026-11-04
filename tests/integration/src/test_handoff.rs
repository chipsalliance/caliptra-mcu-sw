// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use crate::test_hek::test::setup_otp_hek;
    use caliptra_mcu_builder::FirmwareBinaries;
    use caliptra_mcu_hw_model::DefaultHwModel;
    use caliptra_mcu_hw_model::McuHwModel;

    fn start_handoff_model(feature: &str, active_slot: usize) -> DefaultHwModel {
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            binaries
                .test_runtime(feature)
                .expect("Handoff test requires its feature-specific firmware in the bundle");
            assert!(
                binaries.has_test_feature_rom("ocp-lock"),
                "Handoff test requires the matching OCP LOCK ROM in the bundle"
            );
        }
        let mut otp = vec![0u8; 4096];
        setup_otp_hek(&mut otp, active_slot, false, false);
        let profile_override = std::env::var("MCU_TEST_PROFILE").ok();
        let profile = profile_override.as_deref().unwrap_or("release");

        start_runtime_hw_model(TestParams {
            otp_memory: Some(otp),
            rom_only: false,
            ocp_lock_en: true,
            feature: Some(feature),
            rom_feature: Some("ocp-lock"),
            profile: (feature == "test-handoff-syscalls").then_some(profile),
            ..Default::default()
        })
    }

    fn expect_handoff_failure(_test_name: &str, feature: &str) {
        #[cfg(not(feature = "fpga_realtime"))]
        {
            const CHILD_ENV: &str = "CALIPTRA_MCU_HANDOFF_FAILURE_CHILD";
            if std::env::var_os(CHILD_ENV).is_none() {
                // EmuCtrl exits the host process with the firmware's exit code.
                // A child lets us distinguish the expected code from a panic,
                // a signal, or the old false-success exit.
                let status = std::process::Command::new(
                    std::env::current_exe().expect("Failed to locate handoff test executable"),
                )
                .args(["--exact", _test_name, "--nocapture"])
                .env(CHILD_ENV, "1")
                .status()
                .expect("Failed to start negative handoff test");
                assert_eq!(
                    status.code(),
                    Some(1),
                    "Expected firmware failure, got {status}"
                );
                return;
            }
        }
        let _lock = TEST_LOCK.lock().unwrap();
        let mut hw = start_handoff_model(feature, 3);
        let error = hw
            .step_until_exit_success()
            .expect_err("The handoff test must reject the wrong HEK slot");
        assert_eq!(error.to_string(), "firmware exited with failure");
        #[cfg(not(feature = "fpga_realtime"))]
        std::process::exit(1);
    }

    #[test]
    fn test_handoff_integrity() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut hw = start_handoff_model("test-handoff", 2);
        hw.step_until_exit_success()
            .expect("HandOff verification failed in runtime");
    }

    #[test]
    fn test_handoff_integrity_failure_is_not_overwritten() {
        expect_handoff_failure(
            "test_handoff::test::test_handoff_integrity_failure_is_not_overwritten",
            "test-handoff",
        );
    }

    #[cfg(not(feature = "fpga_realtime"))]
    #[test]
    fn test_handoff_syscalls_release() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut hw = start_handoff_model("test-handoff-syscalls", 2);
        hw.step_until_exit_success()
            .expect("Release handoff syscalls did not return ROM-produced values");
    }

    #[cfg(not(feature = "fpga_realtime"))]
    #[test]
    fn test_handoff_syscalls_reject_wrong_hek() {
        expect_handoff_failure(
            "test_handoff::test::test_handoff_syscalls_reject_wrong_hek",
            "test-handoff-syscalls",
        );
    }
}
