// Licensed under the Apache-2.0 license

//! This module tests MCTP control commands functionality.

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_pldm_ua::transport::{EndpointId, PldmTransport};
    use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
    use caliptra_mcu_testing_common::mctp_transport::MctpTransport;
    use caliptra_mcu_testing_common::pldm_request_response::PldmRequestResponseTest;
    use random_port::PortPicker;

    #[test]
    fn test_pldm_request_response() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        for (mcu_feature, test_feature, build_example_app) in [
            (
                "test-pldm-request-response",
                "test-pldm-request-response",
                true,
            ),
            ("test-pldm-discovery", "test-pldm-discovery", false),
            ("test-pldm-discovery", "test-pldm-fw-update", false),
        ] {
            let mut hw = start_runtime_hw_model(TestParams {
                feature: Some(mcu_feature),
                example_app: build_example_app,
                i3c_port: Some(PortPicker::new().pick().unwrap()),
                ..Default::default()
            });

            hw.start_i3c_controller();

            let pldm_transport = MctpTransport::new(
                hw.i3c_port().unwrap(),
                DynamicI3cAddress::from(hw.i3c_address().unwrap()),
            );
            let pldm_socket = pldm_transport
                .create_socket(EndpointId(0), EndpointId(1))
                .unwrap();

            PldmRequestResponseTest::run(pldm_socket, test_feature.to_string());

            let test = finish_runtime_hw_model(&mut hw);
            assert_eq!(0, test);
        }

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
