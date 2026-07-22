// Licensed under the Apache-2.0 license

//! SPDM attestation test over MCTP transport using PCR Quote measurement format

#[cfg(test)]
mod test {
    use crate::test::{
        finish_runtime_hw_model, run_imaginary_flash_controller_service, start_runtime_hw_model,
        TestParams, TEST_LOCK,
    };
    use crate::test_mctp_spdm_attestation::test::{
        assert_spdm_attestation_artifacts, remove_spdm_attestation_artifacts,
        run_mctp_spdm_attestation_test,
    };
    use caliptra_mcu_hw_model::McuHwModel;
    use random_port::PortPicker;
    use std::time::Duration;

    const TEST_NAME: &str = "MCTP-SPDM-ATTESTATION-PCR-QUOTE";

    #[ignore]
    #[test]
    fn test_mctp_spdm_attestation_pcr_quote() {
        if std::env::var("SPDM_VALIDATOR_DIR").is_err() {
            println!("SPDM_VALIDATOR_DIR environment variable is not set. Skipping test");
            return;
        }
        remove_spdm_attestation_artifacts();

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-mctp-spdm-attestation-pcr-quote"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            use_strap_secrets: true,
            ..Default::default()
        });

        run_imaginary_flash_controller_service(&mut hw);

        hw.start_i3c_controller();

        run_mctp_spdm_attestation_test(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            PortPicker::new().pick().unwrap(),
            Duration::from_secs(9000),
            TEST_NAME,
        );

        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);
        assert_spdm_attestation_artifacts();

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
