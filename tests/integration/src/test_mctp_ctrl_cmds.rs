// Licensed under the Apache-2.0 license

//! This module tests MCTP control commands functionality.

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
    use caliptra_mcu_testing_common::i3c_socket;
    use caliptra_mcu_testing_common::mctp_ctrl_cmds::MCTPCtrlCmdTests;
    use random_port::PortPicker;

    #[test]
    fn test_mctp_ctrl_cmds() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let tests = MCTPCtrlCmdTests::generate_tests();

        i3c_socket::run_tests(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            tests,
            None,
        );

        let test = finish_runtime_hw_model(&mut hw);
        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
