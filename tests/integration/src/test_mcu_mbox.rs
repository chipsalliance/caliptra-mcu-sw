// Licensed under the Apache-2.0 license

#[cfg(feature = "fpga_realtime")]
#[cfg(test)]
pub mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::mcu_mbox_transport::{
        McuMailboxError, McuMailboxResponse, McuMailboxTransport,
    };
    use mcu_hw_model::McuHwModel;
    use mcu_mbox_common::messages::{
        CmDeleteReq, CmImportReq, CmKeyUsage, CmRandomGenerateReq, CmRandomStirReq, CmShaFinalReq,
        CmShaFinalResp, CmShaInitReq, CmShaUpdateReq, Cmk, DeviceCapsReq, DeviceCapsResp,
        DeviceIdReq, DeviceIdResp, DeviceInfoReq, DeviceInfoResp, FirmwareVersionReq,
        FirmwareVersionResp, MailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize,
        McuCmDeleteReq, McuCmImportReq, McuCmImportResp, McuCmStatusReq, McuCmStatusResp,
        McuMailboxReq, McuMailboxResp, McuRandomGenerateReq, McuRandomStirReq, McuShaFinalReq,
        McuShaFinalResp, McuShaInitReq, McuShaInitResp, McuShaUpdateReq, DEVICE_CAPS_SIZE,
        MAX_CMB_DATA_SIZE,
    };
    use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
    use random_port::PortPicker;
    use registers_generated::mci;
    use sha2::{Digest, Sha384, Sha512};
    use std::process::exit;
    use std::sync::atomic::Ordering;
    use zerocopy::{FromBytes, IntoBytes};

    #[test]
    pub fn test_mcu_mbox_cmds() {
        start_mcu_mbox_tests("test-mcu-mbox-cmds");
    }

    #[test]
    pub fn test_mcu_mbox_usermode() {
        start_mcu_mbox_tests("test-mcu-mbox-usermode");
    }

    fn start_mcu_mbox_tests(feature: &str) {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
        let feature = feature.replace("_", "-");

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(&feature),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            ..Default::default()
        });

        hw.start_i3c_controller();
        let mci_ptr = hw.base.mmio.mci().unwrap().ptr as u64;

        std::thread::spawn(move || {
            wait_for_runtime_start();
            if !MCU_RUNNING.load(Ordering::Relaxed) {
                exit(-1);
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
            let mci_base = unsafe { romtime::StaticRef::new(mci_ptr as *const mci::regs::Mci) };
            let mbox_transport = McuMailboxTransport::new(mci_base);
            println!("MCU MBOX Test Thread Starting:");
            let mut test = RequestResponseTest::new(mbox_transport);

            if test.direct_test_process_and_check(&feature).is_err() {
                println!("Failed");
                exit(-1);
            }

            if test.test_send_receive(&feature).is_err() {
                println!("Failed");
                exit(-1);
            } else {
                println!("Sent {} test messages", test.test_messages.len());
                println!("Passed");
            }
            MCU_RUNNING.store(false, Ordering::Relaxed);
        });

        let test = finish_runtime_hw_model(&mut hw);
        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, Ordering::Relaxed);
    }

    struct RequestResponseTest {
        test_messages: Vec<ExpectedMessagePair>,
        mbox: McuMailboxTransport,
    }

    #[derive(Clone)]
    struct ExpectedMessagePair {
        // Important! Ensure that data are 4-byte aligned
        // Message Sent
        pub cmd: u32,
        pub request: Vec<u8>,
        // Expected Message Response to receive
        pub response: Vec<u8>,
    }

    #[allow(dead_code)]
    #[repr(u32)]
    enum MbxCmdStatus {
        /// The command is still being processed.
        Busy = 0,
        /// Data is available to be read.
        DataReady = 1,
        /// The command completed successfully.
        Complete = 2,
        /// The command failed.
        Failure = 3,
    }

    impl RequestResponseTest {
        pub fn new(mbox: McuMailboxTransport) -> Self {
            let test_messages: Vec<ExpectedMessagePair> = Vec::new();
            Self {
                test_messages,
                mbox,
            }
        }

        fn process_message(
            &mut self,
            cmd: u32,
            request: &[u8],
        ) -> Result<McuMailboxResponse, McuMailboxError> {
            self.mbox.execute(cmd, request)?;

            let timeout = std::time::Duration::from_secs(20);
            let start = std::time::Instant::now();
            loop {
                match self.mbox.get_execute_response() {
                    Ok(resp) => return Ok(resp),
                    Err(McuMailboxError::Busy) => {
                        if start.elapsed() > timeout {
                            // Print out timeout error and cmd id
                            println!(
                                "Timeout waiting for response for MCU mailbox cmd: {:#X}",
                                cmd
                            );
                            return Err(McuMailboxError::Timeout);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        fn prep_test_messages(&mut self, feature: &str) {
            if feature == "test-mcu-mbox-usermode" {
                println!("Running test-mcu-mbox-usermode test");
                self.add_usermode_loopback_tests();
            } else if feature == "test-mcu-mbox-cmds" {
                println!("Running test-mcu-mbox-cmds test");
                self.add_basic_cmds_tests();
                self.add_sha_simple_tests();
                self.add_sha_partial_update_tests();
                self.add_sha_variable_length_tests();
            }
        }

        fn push(&mut self, cmd: u32, req_payload: Vec<u8>, resp_payload: Vec<u8>) {
            self.test_messages.push(ExpectedMessagePair {
                cmd,
                request: req_payload,
                response: resp_payload,
            });
        }

        #[allow(clippy::result_unit_err)]
        fn test_send_receive(&mut self, feature: &str) -> Result<(), ()> {
            self.prep_test_messages(feature);
            let test_messages = self.test_messages.clone();
            for message_pair in &test_messages {
                let actual_response = self
                    .process_message(message_pair.cmd, &message_pair.request)
                    .map_err(|_| ())?;
                assert_eq!(actual_response.data, message_pair.response);
            }
            Ok(())
        }

        fn direct_test_process_and_check(&mut self, feature: &str) -> Result<(), ()> {
            if feature == "test-mcu-mbox-cmds" {
                self.add_import_delete_tests()?;
                self.add_rng_generate_tests()?;
                self.add_rng_stir_etrng_not_supported_test()?;
                Ok(())
            } else {
                Ok(())
            }
        }

        fn add_usermode_loopback_tests(&mut self) {
            // Construct 256 test messages with payload lengths from 1 to 256
            for len in 1..=256 {
                let payload: Vec<u8> = (0..len).map(|j| (j % 256) as u8).collect();
                let cmd = if len % 2 == 0 { 0x03 } else { 0x04 };
                self.push(cmd, payload.clone(), payload);
            }
            println!(
                "Added {} usermode loopback test messages",
                self.test_messages.len()
            );
        }

        fn add_basic_cmds_tests(&mut self) {
            // Add firmware version test messages
            for idx in 0..=2 {
                let version_str = match idx {
                    0 => mcu_mbox_common::config::TEST_FIRMWARE_VERSIONS[0],
                    1 => mcu_mbox_common::config::TEST_FIRMWARE_VERSIONS[1],
                    2 => mcu_mbox_common::config::TEST_FIRMWARE_VERSIONS[2],
                    _ => unreachable!(),
                };

                let mut fw_version_req = McuMailboxReq::FirmwareVersion(FirmwareVersionReq {
                    hdr: MailboxReqHeader::default(),
                    index: idx,
                });
                let cmd = fw_version_req.cmd_code();
                fw_version_req.populate_chksum().unwrap();

                let mut fw_version_resp = McuMailboxResp::FirmwareVersion(FirmwareVersionResp {
                    hdr: MailboxRespHeaderVarSize {
                        data_len: version_str.len() as u32,
                        ..Default::default()
                    },
                    version: {
                        let mut ver = [0u8; 32];
                        let bytes = version_str.as_bytes();
                        let len = bytes.len().min(ver.len());
                        ver[..len].copy_from_slice(&bytes[..len]);
                        ver
                    },
                });
                fw_version_resp.populate_chksum().unwrap();

                self.push(
                    cmd.0,
                    fw_version_req.as_bytes().unwrap().to_vec(),
                    fw_version_resp.as_bytes().unwrap().to_vec(),
                );
            }

            // Add device cap test message
            let mut device_caps_req = McuMailboxReq::DeviceCaps(DeviceCapsReq::default());
            let cmd = device_caps_req.cmd_code();
            device_caps_req.populate_chksum().unwrap();

            let test_capabilities = &mcu_mbox_common::config::TEST_DEVICE_CAPABILITIES;
            let mut device_caps_resp = McuMailboxResp::DeviceCaps(DeviceCapsResp {
                hdr: MailboxRespHeader::default(),
                caps: {
                    let mut c = [0u8; DEVICE_CAPS_SIZE];
                    c[..test_capabilities.as_bytes().len()]
                        .copy_from_slice(test_capabilities.as_bytes());
                    c
                },
            });
            device_caps_resp.populate_chksum().unwrap();

            self.push(
                cmd.0,
                device_caps_req.as_bytes().unwrap().to_vec(),
                device_caps_resp.as_bytes().unwrap().to_vec(),
            );

            // Add device ID test message
            let mut device_id_req = McuMailboxReq::DeviceId(DeviceIdReq {
                hdr: MailboxReqHeader::default(),
            });
            let cmd = device_id_req.cmd_code();
            device_id_req.populate_chksum().unwrap();

            let test_device_id = &mcu_mbox_common::config::TEST_DEVICE_ID;
            let mut device_id_resp = McuMailboxResp::DeviceId(DeviceIdResp {
                hdr: MailboxRespHeader::default(),
                vendor_id: test_device_id.vendor_id,
                device_id: test_device_id.device_id,
                subsystem_vendor_id: test_device_id.subsystem_vendor_id,
                subsystem_id: test_device_id.subsystem_id,
            });
            device_id_resp.populate_chksum().unwrap();

            self.push(
                cmd.0,
                device_id_req.as_bytes().unwrap().to_vec(),
                device_id_resp.as_bytes().unwrap().to_vec(),
            );

            // Add device info test message
            let mut device_info_req = McuMailboxReq::DeviceInfo(DeviceInfoReq {
                hdr: MailboxReqHeader::default(),
                index: 0, // Only index 0 (UID) is supported in this test
            });
            let cmd = device_info_req.cmd_code();
            device_info_req.populate_chksum().unwrap();

            let test_uid = &mcu_mbox_common::config::TEST_UID;
            let mut device_info_resp = McuMailboxResp::DeviceInfo(DeviceInfoResp {
                hdr: MailboxRespHeaderVarSize {
                    data_len: test_uid.len() as u32,
                    ..Default::default()
                },
                data: {
                    let mut u = [0u8; 32];
                    let len = test_uid.len().min(u.len());
                    u[..len].copy_from_slice(&test_uid[..len]);
                    u
                },
            });
            device_info_resp.populate_chksum().unwrap();

            self.push(
                cmd.0,
                device_info_req.as_bytes().unwrap().to_vec(),
                device_info_resp.as_bytes().unwrap().to_vec(),
            );
        }

        fn add_sha_simple_tests(&mut self) {
            // Test both SHA384 and SHA512 with input "a" repeated 129 times
            for (hash_algorithm, hash_size) in [(1, 48), (2, 64)] {
                let input_data = "a".repeat(129);
                let input_data = input_data.as_bytes();

                // Build and send McuShaInitReq
                let mut sha_init_req = McuMailboxReq::ShaInit(McuShaInitReq(CmShaInitReq {
                    hdr: MailboxReqHeader::default(),
                    hash_algorithm,
                    input_size: input_data.len() as u32,
                    input: {
                        let mut input_arr = [0u8; MAX_CMB_DATA_SIZE];
                        input_arr[..input_data.len()].copy_from_slice(input_data);
                        input_arr
                    },
                }));
                sha_init_req.populate_chksum().unwrap();

                let sha_init_resp_bytes = self
                    .process_message(sha_init_req.cmd_code().0, sha_init_req.as_bytes().unwrap())
                    .expect("Failed to process McuShaInitReq")
                    .data;

                let sha_init_resp = McuShaInitResp::ref_from_bytes(&sha_init_resp_bytes)
                    .expect("Failed to parse McuShaInitResp");

                // Build McuShaFinalReq using context from init response
                let mut sha_final_req = McuMailboxReq::ShaFinal(McuShaFinalReq(CmShaFinalReq {
                    context: sha_init_resp.0.context,
                    ..Default::default()
                }));
                sha_final_req.populate_chksum().unwrap();

                // Calculate expected hash
                let expected_hash = if hash_algorithm == 1 {
                    let mut hasher = Sha384::new();
                    hasher.update(input_data);
                    let hash = hasher.finalize();
                    let mut arr = [0u8; 64];
                    arr[..48].copy_from_slice(hash.as_bytes());
                    arr
                } else {
                    let mut hasher = Sha512::new();
                    hasher.update(input_data);
                    let hash = hasher.finalize();
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(hash.as_bytes());
                    arr
                };

                // Build expected McuShaFinalResp
                let mut expected_final_resp =
                    McuMailboxResp::ShaFinal(McuShaFinalResp(CmShaFinalResp {
                        hdr: MailboxRespHeaderVarSize {
                            data_len: hash_size as u32,
                            ..Default::default()
                        },
                        hash: expected_hash,
                    }));
                expected_final_resp.populate_chksum().unwrap();

                // Push the test message pair for SHA final
                self.push(
                    sha_final_req.cmd_code().0,
                    sha_final_req.as_bytes().unwrap().to_vec(),
                    expected_final_resp.as_bytes().unwrap().to_vec(),
                );
            }
        }

        fn add_sha_partial_update_tests(&mut self) {
            for (sha, hash_size) in [(1, 48), (2, 64)] {
                let input_str = "a".repeat(2048);
                let original_input_data = input_str.as_bytes();
                let mut input_data = input_str.as_bytes().to_vec();
                let mut input_data = input_data.as_mut_slice();
                let split = 32;
                let initial = 1024;
                // SHA Init
                let mut req = CmShaInitReq {
                    hash_algorithm: sha,
                    input_size: initial as u32,
                    ..Default::default()
                };
                req.input[..initial].copy_from_slice(&input_data[..initial]);
                input_data = &mut input_data[initial..];

                let mut sha_init_req = McuMailboxReq::ShaInit(McuShaInitReq(req));
                sha_init_req.populate_chksum().unwrap();

                let sha_init_resp_bytes = self
                    .process_message(sha_init_req.cmd_code().0, sha_init_req.as_bytes().unwrap())
                    .expect("Failed to process McuShaInitReq")
                    .data;
                let mut sha_init_resp = McuShaInitResp::ref_from_bytes(&sha_init_resp_bytes)
                    .expect("Failed to parse McuShaInitResp");

                let mut sha_update_resp_bytes: Vec<u8>;
                // SHA Update (partial)
                while input_data.len() > split {
                    let mut req = CmShaUpdateReq {
                        input_size: split as u32,
                        context: sha_init_resp.0.context,
                        ..Default::default()
                    };
                    req.input[..split].copy_from_slice(&input_data[..split]);

                    let mut sha_update_req = McuMailboxReq::ShaUpdate(McuShaUpdateReq(req));
                    sha_update_req.populate_chksum().unwrap();
                    sha_update_resp_bytes = self
                        .process_message(
                            sha_update_req.cmd_code().0,
                            sha_update_req.as_bytes().unwrap(),
                        )
                        .expect("Failed to process McuShaUpdateReq")
                        .data;

                    sha_init_resp = McuShaInitResp::ref_from_bytes(&sha_update_resp_bytes)
                        .expect("Failed to parse McuShaUpdateResp");
                    input_data = &mut input_data[split..];
                }

                // SHA Final
                let mut req = CmShaFinalReq {
                    input_size: input_data.len() as u32,
                    context: sha_init_resp.0.context,
                    ..Default::default()
                };
                req.input[..input_data.len()].copy_from_slice(input_data);
                let mut sha_final_req = McuMailboxReq::ShaFinal(McuShaFinalReq(req));
                sha_final_req.populate_chksum().unwrap();

                // Calculate expected hash
                let expected_hash = if sha == 1 {
                    let mut hasher = Sha384::new();
                    hasher.update(original_input_data);
                    let hash = hasher.finalize();
                    let mut arr = [0u8; 64];
                    arr[..48].copy_from_slice(hash.as_bytes());
                    arr
                } else {
                    let mut hasher = Sha512::new();
                    hasher.update(original_input_data);
                    let hash = hasher.finalize();
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(hash.as_bytes());
                    arr
                };

                // Build expected McuShaFinalResp
                let mut expected_final_resp =
                    McuMailboxResp::ShaFinal(McuShaFinalResp(CmShaFinalResp {
                        hdr: MailboxRespHeaderVarSize {
                            data_len: hash_size as u32,
                            ..Default::default()
                        },
                        hash: expected_hash,
                    }));
                expected_final_resp.populate_chksum().unwrap();

                // Push the test message pair for SHA final
                self.push(
                    sha_final_req.cmd_code().0,
                    sha_final_req.as_bytes().unwrap().to_vec(),
                    expected_final_resp.as_bytes().unwrap().to_vec(),
                );
            }
        }

        fn add_sha_variable_length_tests(&mut self) {
            // Cut down on data size to accommodate mcu mbox message buffer(app) limits
            const MCU_MAX_CMB_DATA_SIZE: usize = MAX_CMB_DATA_SIZE / 2;
            // Add SHA384 and SHA512 variable-length tests
            for sha in [1, 2] {
                // 233 is a prime so should exercise different edge cases in sizes but not take too long
                for i in (0..MCU_MAX_CMB_DATA_SIZE).step_by(233) {
                    let input_str = "a".repeat(i);
                    let input_copy = input_str.clone();
                    let original_input_data = input_copy.as_bytes();
                    let mut input_data = input_str.as_bytes().to_vec();
                    let mut input_data = input_data.as_mut_slice();
                    let process = input_data.len().min(MCU_MAX_CMB_DATA_SIZE);
                    // SHA Init
                    let mut req: CmShaInitReq = CmShaInitReq {
                        hash_algorithm: sha,
                        input_size: process as u32,
                        ..Default::default()
                    };
                    req.input[..process].copy_from_slice(&input_data[..process]);
                    input_data = &mut input_data[process..];

                    let mut sha_init_req = McuMailboxReq::ShaInit(McuShaInitReq(req));
                    sha_init_req.populate_chksum().unwrap();

                    let sha_init_resp_bytes = self
                        .process_message(
                            sha_init_req.cmd_code().0,
                            sha_init_req.as_bytes().unwrap(),
                        )
                        .expect("Failed to process McuShaInitReq")
                        .data;
                    let mut sha_init_resp = McuShaInitResp::ref_from_bytes(&sha_init_resp_bytes)
                        .expect("Failed to parse McuShaInitResp");

                    let mut sha_update_resp_bytes: Vec<u8>;
                    // SHA Update (partial)
                    while input_data.len() > MCU_MAX_CMB_DATA_SIZE {
                        let mut req = CmShaUpdateReq {
                            input_size: MCU_MAX_CMB_DATA_SIZE as u32,
                            context: sha_init_resp.0.context,
                            ..Default::default()
                        };
                        req.input
                            .copy_from_slice(&input_data[..MCU_MAX_CMB_DATA_SIZE]);

                        let mut sha_update_req = McuMailboxReq::ShaUpdate(McuShaUpdateReq(req));
                        sha_update_req.populate_chksum().unwrap();

                        sha_update_resp_bytes = self
                            .process_message(
                                sha_update_req.cmd_code().0,
                                sha_update_req.as_bytes().unwrap(),
                            )
                            .expect("Failed to process McuShaUpdateReq")
                            .data;

                        sha_init_resp = McuShaInitResp::ref_from_bytes(&sha_update_resp_bytes)
                            .expect("Failed to parse McuShaUpdateResp");
                        input_data = &mut input_data[MCU_MAX_CMB_DATA_SIZE..];
                    }

                    // SHA Final
                    let mut req = CmShaFinalReq {
                        input_size: input_data.len() as u32,
                        context: sha_init_resp.0.context,
                        ..Default::default()
                    };
                    req.input[..input_data.len()].copy_from_slice(input_data);

                    let mut sha_final_req = McuMailboxReq::ShaFinal(McuShaFinalReq(req));
                    sha_final_req.populate_chksum().unwrap();

                    // Calculate expected hash
                    let (hash_size, expected_hash) = if sha == 1 {
                        let mut hasher = Sha384::new();
                        hasher.update(original_input_data);
                        let hash = hasher.finalize();
                        (48, {
                            let mut arr = [0u8; 64];
                            arr[..48].copy_from_slice(hash.as_bytes());
                            arr
                        })
                    } else {
                        let mut hasher = Sha512::new();
                        hasher.update(original_input_data);
                        let hash = hasher.finalize();
                        (64, {
                            let mut arr = [0u8; 64];
                            arr.copy_from_slice(hash.as_bytes());
                            arr
                        })
                    };
                    // Build expected McuShaFinalResp
                    let mut expected_final_resp =
                        McuMailboxResp::ShaFinal(McuShaFinalResp(CmShaFinalResp {
                            hdr: MailboxRespHeaderVarSize {
                                data_len: hash_size as u32,
                                ..Default::default()
                            },
                            hash: expected_hash,
                        }));
                    expected_final_resp.populate_chksum().unwrap();

                    // Push the test message pair for SHA final
                    self.push(
                        sha_final_req.cmd_code().0,
                        sha_final_req.as_bytes().unwrap().to_vec(),
                        expected_final_resp.as_bytes().unwrap().to_vec(),
                    );
                }
            }
        }

        fn add_import_delete_tests(&mut self) -> Result<(), ()> {
            let cmk = self.import_key(&[0xbb; 32], CmKeyUsage::Aes)?;
            // Check status after import
            self.check_cm_status(1, 256)?;
            // Now delete the key
            self.delete_key(&cmk)?;
            // Check status after delete
            self.check_cm_status(0, 256)?;
            Ok(())
        }

        fn delete_key(&mut self, cmk: &Cmk) -> Result<(), ()> {
            let mut delete_req = McuMailboxReq::Delete(McuCmDeleteReq(CmDeleteReq {
                hdr: MailboxReqHeader::default(),
                cmk: cmk.clone(),
            }));
            delete_req.populate_chksum().unwrap();
            self.process_message(delete_req.cmd_code().0, delete_req.as_bytes().unwrap())
                .map_err(|_| ())?;
            Ok(())
        }

        fn check_cm_status(&mut self, expected_used: u32, expected_total: u32) -> Result<(), ()> {
            let mut status_req = McuMailboxReq::CmStatus(McuCmStatusReq::default());
            status_req.populate_chksum().unwrap();

            let status_resp_bytes = self
                .process_message(status_req.cmd_code().0, status_req.as_bytes().unwrap())
                .map_err(|_| ())?
                .data;
            let status_resp =
                McuCmStatusResp::ref_from_bytes(&status_resp_bytes).map_err(|_| ())?;
            assert_eq!(status_resp.0.used_usage_storage, expected_used);
            assert_eq!(status_resp.0.total_usage_storage, expected_total);
            Ok(())
        }

        fn import_key(&mut self, key: &[u8], key_usage: CmKeyUsage) -> Result<Cmk, ()> {
            let mut input = [0u8; 64];
            input[..key.len()].copy_from_slice(key);

            let mut import_req = McuMailboxReq::Import(McuCmImportReq(CmImportReq {
                hdr: MailboxReqHeader { chksum: 0 },
                key_usage: key_usage.into(),
                input_size: key.len() as u32,
                input,
            }));
            import_req.populate_chksum().unwrap();

            let resp = self
                .process_message(import_req.cmd_code().0, import_req.as_bytes().unwrap())
                .map_err(|_| ())?;
            let import_resp = McuCmImportResp::ref_from_bytes(&resp.data).map_err(|_| ())?;
            assert_eq!(
                import_resp.0.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED
            );
            Ok(import_resp.0.cmk.clone())
        }

        fn add_rng_generate_tests(&mut self) -> Result<(), ()> {
            // Test RNG generate for different lengths
            for req_len in [0usize, 1, 47, 48, 256] {
                let mut rng_generate_req =
                    McuMailboxReq::RandomGenerate(McuRandomGenerateReq(CmRandomGenerateReq {
                        hdr: MailboxReqHeader::default(),
                        size: req_len as u32,
                    }));
                rng_generate_req.populate_chksum().unwrap();

                let resp = self
                    .process_message(
                        rng_generate_req.cmd_code().0,
                        rng_generate_req.as_bytes().unwrap(),
                    )
                    .map_err(|_| ())?
                    .data;

                // Get the length from the response header (variable header)
                const VAR_HEADER_SIZE: usize = std::mem::size_of::<MailboxRespHeaderVarSize>();
                let resp_hdr = MailboxRespHeaderVarSize::read_from_bytes(&resp[..VAR_HEADER_SIZE])
                    .map_err(|_| ())?;
                assert_eq!(resp_hdr.data_len as usize, req_len);

                // Check random data generated is non-zero for lengths > 0
                if req_len > 0 {
                    let random_data = &resp[VAR_HEADER_SIZE..VAR_HEADER_SIZE + req_len];
                    assert!(
                        random_data.iter().copied().reduce(|a, b| (a | b)).unwrap() != 0,
                        "Random data should not be all-zeros"
                    );
                }
            }
            Ok(())
        }

        fn add_rng_stir_etrng_not_supported_test(&mut self) -> Result<(), ()> {
            let mut rng_stir_req = McuMailboxReq::RandomStir(McuRandomStirReq(CmRandomStirReq {
                hdr: MailboxReqHeader::default(),
                input_size: 1u32,
                input: [0xff; MAX_CMB_DATA_SIZE],
            }));
            rng_stir_req.populate_chksum().unwrap();

            let resp = self
                .process_message(rng_stir_req.cmd_code().0, rng_stir_req.as_bytes().unwrap())
                .map_err(|_| ())?;

            assert_eq!(resp.status_code, MbxCmdStatus::Complete as u32);

            Ok(())
        }
    }
}
