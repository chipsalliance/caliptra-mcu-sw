//! Licensed under the Apache-2.0 license

//! This module tests the PLDM Firmware Update

#[cfg(test)]
mod test {
    use crate::test::{
        compile_runtime, finish_runtime_hw_model, start_runtime_hw_model, ROM, TEST_LOCK,
    };
    use chrono::{TimeZone, Utc};
    use lazy_static::lazy_static;
    use log::{error, LevelFilter};
    use mcu_hw_model::McuHwModel;
    use mcu_testing_common::i3c_socket::{self, BufferedStream, MctpTestState, MctpTransportTest};
    use mcu_testing_common::mctp_transport::{MctpPldmSocket, MctpTransport};
    use mcu_testing_common::mctp_util::common::MctpUtil;
    use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
    use pldm_common::protocol::firmware_update::*;
    use pldm_fw_pkg::{
        manifest::{
            ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
            PackageHeaderInformation, StringType,
        },
        FirmwareManifest,
    };
    use pldm_ua::daemon::Options;
    use pldm_ua::daemon::PldmDaemon;
    use pldm_ua::transport::{EndpointId, PldmSocket, PldmTransport};
    use pldm_ua::{discovery_sm, update_sm};
    use simple_logger::SimpleLogger;
    use std::process::exit;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use uuid::Uuid;

    #[cfg_attr(feature = "fpga_realtime", ignore)]
    #[test]
    fn test_mctp_capsule_loopback() {
        let feature = "test-mctp-capsule-loopback";
        let example_app = false;
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        println!("Compiling test firmware {}", feature);
        let feature = feature.replace("_", "-");
        let test_runtime = compile_runtime(&feature, example_app);
        let mut hw = start_runtime_hw_model(ROM.to_path_buf(), test_runtime, Some(65534));

        hw.start_i3c_controller();

        // let pldm_transport =
        //     MctpTransport::new(hw.i3c_port().unwrap(), hw.i3c_address().unwrap().into());
        // let pldm_socket = pldm_transport
        //     .create_socket(EndpointId(8), EndpointId(0))
        //     .unwrap();
        // PldmFwUpdateTest::run(pldm_socket);

        let tests = generate_tests();
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

    pub(crate) fn generate_tests() -> Vec<Box<dyn MctpTransportTest + Send>> {
        vec![Box::new(Test::new("MctpMultiPktTest")) as Box<dyn MctpTransportTest + Send>]
    }

    struct Test {
        test_name: String,
        test_state: MctpTestState,
        loopback_msg: Vec<u8>,
        mctp_util: MctpUtil,
        passed: bool,
    }

    impl Test {
        fn new(test_name: &str) -> Self {
            Test {
                test_name: test_name.to_string(),
                test_state: MctpTestState::Start,
                loopback_msg: Vec::new(),
                mctp_util: MctpUtil::new(),
                passed: false,
            }
        }
    }

    impl MctpTransportTest for Test {
        fn is_passed(&self) -> bool {
            self.passed
        }

        fn run_test(&mut self, stream: &mut BufferedStream, target_addr: u8) {
            stream.set_nonblocking(true).unwrap();

            while MCU_RUNNING.load(Ordering::Relaxed) {
                match self.test_state {
                    MctpTestState::Start => {
                        println!("Starting test: {}", self.test_name);
                        self.test_state = MctpTestState::ReceiveReq;
                    }
                    MctpTestState::ReceiveReq => {
                        self.loopback_msg =
                            self.mctp_util.receive_request(stream, target_addr, None);
                        self.test_state = MctpTestState::SendResp;
                    }
                    MctpTestState::SendResp => {
                        self.mctp_util.send_response(
                            self.loopback_msg.as_slice(),
                            stream,
                            target_addr,
                        );

                        self.test_state = MctpTestState::ReceiveReq;
                    }
                    MctpTestState::Finish => {
                        self.passed = true;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}
