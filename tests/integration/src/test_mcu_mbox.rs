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
        CmAesDecryptInitReq, CmAesDecryptUpdateReq, CmAesEncryptInitReq,
        CmAesEncryptInitRespHeader, CmAesEncryptUpdateReq, CmAesGcmDecryptFinalReq,
        CmAesGcmDecryptFinalRespHeader, CmAesGcmDecryptInitReq, CmAesGcmDecryptUpdateReq,
        CmAesGcmDecryptUpdateRespHeader, CmAesGcmEncryptFinalReq, CmAesGcmEncryptFinalRespHeader,
        CmAesGcmEncryptInitReq, CmAesGcmEncryptUpdateReq, CmAesGcmEncryptUpdateRespHeader,
        CmAesMode, CmAesRespHeader, CmDeleteReq, CmImportReq, CmKeyUsage, CmRandomGenerateReq,
        CmRandomStirReq, CmShaFinalReq, CmShaFinalResp, CmShaInitReq, CmShaUpdateReq, Cmk,
        DeviceCapsReq, DeviceCapsResp, DeviceIdReq, DeviceIdResp, DeviceInfoReq, DeviceInfoResp,
        FirmwareVersionReq, FirmwareVersionResp, MailboxReqHeader, MailboxRespHeader,
        MailboxRespHeaderVarSize, McuAesDecryptInitReq, McuAesDecryptUpdateReq,
        McuAesEncryptInitReq, McuAesEncryptUpdateReq, McuAesGcmDecryptFinalReq,
        McuAesGcmDecryptInitReq, McuAesGcmDecryptUpdateReq, McuAesGcmEncryptFinalReq,
        McuAesGcmEncryptInitReq, McuAesGcmEncryptUpdateReq, McuCmDeleteReq, McuCmImportReq,
        McuCmImportResp, McuCmStatusReq, McuCmStatusResp, McuMailboxReq, McuMailboxResp,
        McuRandomGenerateReq, McuRandomStirReq, McuShaFinalReq, McuShaFinalResp, McuShaInitReq,
        McuShaInitResp, McuShaUpdateReq, CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE, DEVICE_CAPS_SIZE,
        MAX_CMB_DATA_SIZE,
    };
    use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
    use random_port::PortPicker;
    use registers_generated::mci;
    use sha2::{Digest, Sha384, Sha512};
    use std::process::exit;
    use std::sync::atomic::Ordering;
    use zerocopy::{FromBytes, IntoBytes};

    /// Chunk size for splitting large AES-GCM payloads.
    /// Set to 2048 to ensure total request (headers ~140 bytes + data) fits within 4K SRAM.
    const AES_GCM_CHUNK_SIZE: usize = 2048;

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
                self.add_aes_encrypt_decrypt_tests()?;
                self.add_aes_gcm_encrypt_decrypt_tests()?;
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

        /// Test AES encrypt and decrypt operations in CBC and CTR modes.
        /// This performs a round-trip test: encrypt plaintext, then decrypt ciphertext,
        /// and verify the result matches the original plaintext.
        fn add_aes_encrypt_decrypt_tests(&mut self) -> Result<(), ()> {
            println!("Running AES encrypt/decrypt tests");

            // Test both CBC and CTR modes
            for mode in [CmAesMode::Cbc, CmAesMode::Ctr] {
                println!("Testing AES mode: {:?}", mode);

                // Import a 256-bit AES key
                let key = [0xaa; 32];
                let cmk = self.import_key(&key, CmKeyUsage::Aes)?;

                // Test various plaintext lengths (for CBC, must be multiple of 16)
                let test_lengths: Vec<usize> = match mode {
                    CmAesMode::Cbc => vec![16, 32, 64, 128, 256], // CBC requires block-aligned
                    CmAesMode::Ctr => vec![1, 15, 16, 17, 32, 64, 100, 256], // CTR can be any length
                    _ => vec![16],
                };

                for len in test_lengths {
                    println!("  Testing plaintext length: {}", len);

                    // Create test plaintext
                    let plaintext: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();

                    // Encrypt the plaintext
                    let (iv, ciphertext) = self.aes_encrypt(&cmk, &plaintext, mode)?;
                    assert_eq!(
                        ciphertext.len(),
                        plaintext.len(),
                        "Ciphertext length should match plaintext length"
                    );

                    // Decrypt the ciphertext
                    let decrypted = self.aes_decrypt(&cmk, &iv, &ciphertext, mode)?;
                    assert_eq!(
                        decrypted.len(),
                        plaintext.len(),
                        "Decrypted length should match plaintext length"
                    );

                    // Verify round-trip
                    assert_eq!(
                        decrypted, plaintext,
                        "Decrypted data should match original plaintext"
                    );

                    println!("    Encrypt/decrypt round-trip successful");
                }

                // Clean up - delete the key
                self.delete_key(&cmk)?;
            }

            println!("AES encrypt/decrypt tests passed");
            Ok(())
        }

        /// Perform AES encryption using Init and optionally Update commands.
        fn aes_encrypt(
            &mut self,
            cmk: &Cmk,
            plaintext: &[u8],
            mode: CmAesMode,
        ) -> Result<([u8; 16], Vec<u8>), ()> {
            let split = MAX_CMB_DATA_SIZE / 2; // Use half the max buffer size for splitting
            let init_len = plaintext.len().min(split);

            // Build AES Encrypt Init request
            let mut init_req = CmAesEncryptInitReq {
                hdr: MailboxReqHeader::default(),
                cmk: cmk.clone(),
                mode: mode as u32,
                plaintext_size: init_len as u32,
                plaintext: [0u8; MAX_CMB_DATA_SIZE],
            };
            init_req.plaintext[..init_len].copy_from_slice(&plaintext[..init_len]);

            let mut mcu_init_req = McuMailboxReq::AesEncryptInit(McuAesEncryptInitReq(init_req));
            mcu_init_req.populate_chksum().unwrap();

            let init_resp = self
                .process_message(mcu_init_req.cmd_code().0, mcu_init_req.as_bytes().unwrap())
                .map_err(|_| ())?;

            // Parse the init response header
            const INIT_HEADER_SIZE: usize = core::mem::size_of::<CmAesEncryptInitRespHeader>();
            let init_resp_hdr =
                CmAesEncryptInitRespHeader::read_from_bytes(&init_resp.data[..INIT_HEADER_SIZE])
                    .map_err(|_| ())?;

            assert_eq!(
                init_resp_hdr.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );
            assert_eq!(
                init_resp_hdr.ciphertext_size as usize, init_len,
                "Init ciphertext size should match input size"
            );

            // Collect the ciphertext from init response
            let mut ciphertext = vec![];
            let ct_len = init_resp_hdr.ciphertext_size as usize;
            ciphertext
                .extend_from_slice(&init_resp.data[INIT_HEADER_SIZE..INIT_HEADER_SIZE + ct_len]);

            let iv = init_resp_hdr.iv;
            let mut context = init_resp_hdr.context;
            let mut remaining = &plaintext[init_len..];

            // Process remaining plaintext with Update commands
            while !remaining.is_empty() {
                let chunk_len = remaining.len().min(split);

                let mut update_req = CmAesEncryptUpdateReq {
                    hdr: MailboxReqHeader::default(),
                    context,
                    plaintext_size: chunk_len as u32,
                    plaintext: [0u8; MAX_CMB_DATA_SIZE],
                };
                update_req.plaintext[..chunk_len].copy_from_slice(&remaining[..chunk_len]);

                let mut mcu_update_req =
                    McuMailboxReq::AesEncryptUpdate(McuAesEncryptUpdateReq(update_req));
                mcu_update_req.populate_chksum().unwrap();

                let update_resp = self
                    .process_message(
                        mcu_update_req.cmd_code().0,
                        mcu_update_req.as_bytes().unwrap(),
                    )
                    .map_err(|_| ())?;

                // Parse update response header
                const UPDATE_HEADER_SIZE: usize = core::mem::size_of::<CmAesRespHeader>();
                let update_resp_hdr =
                    CmAesRespHeader::read_from_bytes(&update_resp.data[..UPDATE_HEADER_SIZE])
                        .map_err(|_| ())?;

                assert_eq!(
                    update_resp_hdr.hdr.fips_status,
                    MailboxRespHeader::FIPS_STATUS_APPROVED,
                    "FIPS status should be approved"
                );
                assert_eq!(
                    update_resp_hdr.output_size as usize, chunk_len,
                    "Update output size should match input size"
                );

                // Collect ciphertext from update response
                let out_len = update_resp_hdr.output_size as usize;
                ciphertext.extend_from_slice(
                    &update_resp.data[UPDATE_HEADER_SIZE..UPDATE_HEADER_SIZE + out_len],
                );

                context = update_resp_hdr.context;
                remaining = &remaining[chunk_len..];
            }

            Ok((iv, ciphertext))
        }

        /// Perform AES decryption using Init and optionally Update commands.
        fn aes_decrypt(
            &mut self,
            cmk: &Cmk,
            iv: &[u8; 16],
            ciphertext: &[u8],
            mode: CmAesMode,
        ) -> Result<Vec<u8>, ()> {
            let split = MAX_CMB_DATA_SIZE / 2;
            let init_len = ciphertext.len().min(split);

            // Build AES Decrypt Init request
            let mut init_req = CmAesDecryptInitReq {
                hdr: MailboxReqHeader::default(),
                cmk: cmk.clone(),
                mode: mode as u32,
                iv: *iv,
                ciphertext_size: init_len as u32,
                ciphertext: [0u8; MAX_CMB_DATA_SIZE],
            };
            init_req.ciphertext[..init_len].copy_from_slice(&ciphertext[..init_len]);

            let mut mcu_init_req = McuMailboxReq::AesDecryptInit(McuAesDecryptInitReq(init_req));
            mcu_init_req.populate_chksum().unwrap();

            let init_resp = self
                .process_message(mcu_init_req.cmd_code().0, mcu_init_req.as_bytes().unwrap())
                .map_err(|_| ())?;

            // Parse the init response (decrypt init uses CmAesResp format)
            const RESP_HEADER_SIZE: usize = core::mem::size_of::<CmAesRespHeader>();
            let init_resp_hdr =
                CmAesRespHeader::read_from_bytes(&init_resp.data[..RESP_HEADER_SIZE])
                    .map_err(|_| ())?;

            assert_eq!(
                init_resp_hdr.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );
            assert_eq!(
                init_resp_hdr.output_size as usize, init_len,
                "Init output size should match input size"
            );

            // Collect the plaintext from init response
            let mut plaintext = vec![];
            let pt_len = init_resp_hdr.output_size as usize;
            plaintext
                .extend_from_slice(&init_resp.data[RESP_HEADER_SIZE..RESP_HEADER_SIZE + pt_len]);

            let mut context = init_resp_hdr.context;
            let mut remaining = &ciphertext[init_len..];

            // Process remaining ciphertext with Update commands
            while !remaining.is_empty() {
                let chunk_len = remaining.len().min(split);

                let mut update_req = CmAesDecryptUpdateReq {
                    hdr: MailboxReqHeader::default(),
                    context,
                    ciphertext_size: chunk_len as u32,
                    ciphertext: [0u8; MAX_CMB_DATA_SIZE],
                };
                update_req.ciphertext[..chunk_len].copy_from_slice(&remaining[..chunk_len]);

                let mut mcu_update_req =
                    McuMailboxReq::AesDecryptUpdate(McuAesDecryptUpdateReq(update_req));
                mcu_update_req.populate_chksum().unwrap();

                let update_resp = self
                    .process_message(
                        mcu_update_req.cmd_code().0,
                        mcu_update_req.as_bytes().unwrap(),
                    )
                    .map_err(|_| ())?;

                // Parse update response header
                let update_resp_hdr =
                    CmAesRespHeader::read_from_bytes(&update_resp.data[..RESP_HEADER_SIZE])
                        .map_err(|_| ())?;

                assert_eq!(
                    update_resp_hdr.hdr.fips_status,
                    MailboxRespHeader::FIPS_STATUS_APPROVED,
                    "FIPS status should be approved"
                );
                assert_eq!(
                    update_resp_hdr.output_size as usize, chunk_len,
                    "Update output size should match input size"
                );

                // Collect plaintext from update response
                let out_len = update_resp_hdr.output_size as usize;
                plaintext.extend_from_slice(
                    &update_resp.data[RESP_HEADER_SIZE..RESP_HEADER_SIZE + out_len],
                );

                context = update_resp_hdr.context;
                remaining = &remaining[chunk_len..];
            }

            Ok(plaintext)
        }

        /// Test AES-GCM encrypt and decrypt operations.
        /// This performs a round-trip test: encrypt plaintext with AAD, then decrypt ciphertext,
        /// verify the tag, and check the result matches the original plaintext.
        fn add_aes_gcm_encrypt_decrypt_tests(&mut self) -> Result<(), ()> {
            println!("Running AES-GCM encrypt/decrypt tests");

            // Import a 256-bit AES key
            let key = [0xbb; 32];
            let cmk = self.import_key(&key, CmKeyUsage::Aes)?;

            // Test cases with various plaintext and AAD lengths
            // Note: MCU mailbox SRAM size is 4K max, so we keep payloads within that limit
            let test_cases: Vec<(usize, usize)> = vec![
                (0, 0),      // Empty plaintext, no AAD
                (16, 0),     // Single block, no AAD
                (1, 16),     // 1 byte plaintext, 16 byte AAD
                (32, 32),    // Two blocks each
                (64, 64),    // Multiple blocks
                (100, 50),   // Non-block-aligned
                (256, 128),  // Larger data
                (512, 256),  // Even larger
                (1024, 512), // Near half capacity
                (2048, 256), // Larger plaintext
            ];

            for (pt_len, aad_len) in test_cases {
                println!(
                    "  Testing plaintext length: {}, AAD length: {}",
                    pt_len, aad_len
                );

                // Create test plaintext and AAD
                let plaintext: Vec<u8> = (0..pt_len).map(|i| (i % 256) as u8).collect();
                let aad: Vec<u8> = (0..aad_len).map(|i| ((i + 128) % 256) as u8).collect();

                // Encrypt the plaintext with AAD
                let (iv, tag, ciphertext) = self.aes_gcm_encrypt(&cmk, &aad, &plaintext)?;

                assert_eq!(
                    ciphertext.len(),
                    plaintext.len(),
                    "Ciphertext length should match plaintext length"
                );

                // Decrypt the ciphertext with AAD and verify tag
                let (tag_verified, decrypted) =
                    self.aes_gcm_decrypt(&cmk, &iv, &aad, &ciphertext, &tag)?;

                assert!(tag_verified, "Tag verification should succeed");
                assert_eq!(
                    decrypted.len(),
                    plaintext.len(),
                    "Decrypted length should match plaintext length"
                );
                assert_eq!(
                    decrypted, plaintext,
                    "Decrypted data should match original plaintext"
                );

                println!("    Encrypt/decrypt round-trip successful");
            }

            // Clean up - delete the key
            self.delete_key(&cmk)?;

            println!("AES-GCM encrypt/decrypt tests passed");
            Ok(())
        }

        /// Perform AES-GCM encryption using Init, Update (optional), and Final commands.
        /// Returns (IV, tag, ciphertext).
        fn aes_gcm_encrypt(
            &mut self,
            cmk: &Cmk,
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<([u8; 12], [u8; 16], Vec<u8>), ()> {
            let split = AES_GCM_CHUNK_SIZE;

            // Build AES-GCM Encrypt Init request
            let mut init_req = CmAesGcmEncryptInitReq {
                hdr: MailboxReqHeader::default(),
                flags: 0,
                cmk: cmk.clone(),
                aad_size: aad.len() as u32,
                aad: [0u8; MAX_CMB_DATA_SIZE],
            };
            if !aad.is_empty() {
                init_req.aad[..aad.len()].copy_from_slice(aad);
            }

            let mut mcu_init_req =
                McuMailboxReq::AesGcmEncryptInit(McuAesGcmEncryptInitReq(init_req));
            mcu_init_req.populate_chksum().unwrap();

            let init_resp = self
                .process_message(mcu_init_req.cmd_code().0, mcu_init_req.as_bytes().unwrap())
                .map_err(|_| ())?;

            // Parse init response to get context and IV
            // CmAesGcmEncryptInitResp has: hdr (MailboxRespHeader), context, iv
            let hdr = MailboxRespHeader::read_from_bytes(
                &init_resp.data[..core::mem::size_of::<MailboxRespHeader>()],
            )
            .map_err(|_| ())?;
            assert_eq!(
                hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );

            let context_start = core::mem::size_of::<MailboxRespHeader>();
            let context_end = context_start + CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE;
            let mut context = [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE];
            context.copy_from_slice(&init_resp.data[context_start..context_end]);

            let iv_start = context_end;
            let mut iv = [0u8; 12];
            iv.copy_from_slice(&init_resp.data[iv_start..iv_start + 12]);

            let mut ciphertext = vec![];
            let mut remaining = plaintext;

            // Process plaintext with Update commands if larger than split
            while remaining.len() > split {
                let chunk_len = split;
                let mut update_req = CmAesGcmEncryptUpdateReq {
                    hdr: MailboxReqHeader::default(),
                    context,
                    plaintext_size: chunk_len as u32,
                    plaintext: [0u8; MAX_CMB_DATA_SIZE],
                };
                update_req.plaintext[..chunk_len].copy_from_slice(&remaining[..chunk_len]);

                let mut mcu_update_req =
                    McuMailboxReq::AesGcmEncryptUpdate(McuAesGcmEncryptUpdateReq(update_req));
                mcu_update_req.populate_chksum().unwrap();

                let update_resp = self
                    .process_message(
                        mcu_update_req.cmd_code().0,
                        mcu_update_req.as_bytes().unwrap(),
                    )
                    .map_err(|_| ())?;

                // Parse update response
                const UPDATE_HEADER_SIZE: usize =
                    core::mem::size_of::<CmAesGcmEncryptUpdateRespHeader>();
                let update_hdr = CmAesGcmEncryptUpdateRespHeader::read_from_bytes(
                    &update_resp.data[..UPDATE_HEADER_SIZE],
                )
                .map_err(|_| ())?;

                assert_eq!(
                    update_hdr.hdr.fips_status,
                    MailboxRespHeader::FIPS_STATUS_APPROVED,
                    "FIPS status should be approved"
                );
                assert_eq!(
                    update_hdr.ciphertext_size as usize, chunk_len,
                    "Update ciphertext size should match input size"
                );

                let ct_len = update_hdr.ciphertext_size as usize;
                ciphertext.extend_from_slice(
                    &update_resp.data[UPDATE_HEADER_SIZE..UPDATE_HEADER_SIZE + ct_len],
                );

                context = update_hdr.context;
                remaining = &remaining[chunk_len..];
            }

            // Final request with remaining plaintext
            let mut final_req = CmAesGcmEncryptFinalReq {
                hdr: MailboxReqHeader::default(),
                context,
                plaintext_size: remaining.len() as u32,
                plaintext: [0u8; MAX_CMB_DATA_SIZE],
            };
            if !remaining.is_empty() {
                final_req.plaintext[..remaining.len()].copy_from_slice(remaining);
            }

            let mut mcu_final_req =
                McuMailboxReq::AesGcmEncryptFinal(McuAesGcmEncryptFinalReq(final_req));
            mcu_final_req.populate_chksum().unwrap();

            let final_resp = self
                .process_message(
                    mcu_final_req.cmd_code().0,
                    mcu_final_req.as_bytes().unwrap(),
                )
                .map_err(|_| ())?;

            // Parse final response
            const FINAL_HEADER_SIZE: usize = core::mem::size_of::<CmAesGcmEncryptFinalRespHeader>();
            let final_hdr = CmAesGcmEncryptFinalRespHeader::read_from_bytes(
                &final_resp.data[..FINAL_HEADER_SIZE],
            )
            .map_err(|_| ())?;

            assert_eq!(
                final_hdr.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );
            assert_eq!(
                final_hdr.ciphertext_size as usize,
                remaining.len(),
                "Final ciphertext size should match input size"
            );

            let ct_len = final_hdr.ciphertext_size as usize;
            ciphertext
                .extend_from_slice(&final_resp.data[FINAL_HEADER_SIZE..FINAL_HEADER_SIZE + ct_len]);

            Ok((iv, final_hdr.tag, ciphertext))
        }

        /// Perform AES-GCM decryption using Init, Update (optional), and Final commands.
        /// Returns (tag_verified, plaintext).
        fn aes_gcm_decrypt(
            &mut self,
            cmk: &Cmk,
            iv: &[u8; 12],
            aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8; 16],
        ) -> Result<(bool, Vec<u8>), ()> {
            let split = AES_GCM_CHUNK_SIZE;

            // Build AES-GCM Decrypt Init request
            let mut init_req = CmAesGcmDecryptInitReq {
                hdr: MailboxReqHeader::default(),
                flags: 0,
                cmk: cmk.clone(),
                iv: *iv,
                aad_size: aad.len() as u32,
                aad: [0u8; MAX_CMB_DATA_SIZE],
            };
            if !aad.is_empty() {
                init_req.aad[..aad.len()].copy_from_slice(aad);
            }

            let mut mcu_init_req =
                McuMailboxReq::AesGcmDecryptInit(McuAesGcmDecryptInitReq(init_req));
            mcu_init_req.populate_chksum().unwrap();

            let init_resp = self
                .process_message(mcu_init_req.cmd_code().0, mcu_init_req.as_bytes().unwrap())
                .map_err(|_| ())?;

            // Parse init response to get context
            // CmAesGcmDecryptInitResp has: hdr (MailboxRespHeader), context
            let hdr = MailboxRespHeader::read_from_bytes(
                &init_resp.data[..core::mem::size_of::<MailboxRespHeader>()],
            )
            .map_err(|_| ())?;
            assert_eq!(
                hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );

            let context_start = core::mem::size_of::<MailboxRespHeader>();
            let context_end = context_start + CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE;
            let mut context = [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE];
            context.copy_from_slice(&init_resp.data[context_start..context_end]);

            let mut plaintext = vec![];
            let mut remaining = ciphertext;

            // Process ciphertext with Update commands if larger than split
            while remaining.len() > split {
                let chunk_len = split;
                let mut update_req = CmAesGcmDecryptUpdateReq {
                    hdr: MailboxReqHeader::default(),
                    context,
                    ciphertext_size: chunk_len as u32,
                    ciphertext: [0u8; MAX_CMB_DATA_SIZE],
                };
                update_req.ciphertext[..chunk_len].copy_from_slice(&remaining[..chunk_len]);

                let mut mcu_update_req =
                    McuMailboxReq::AesGcmDecryptUpdate(McuAesGcmDecryptUpdateReq(update_req));
                mcu_update_req.populate_chksum().unwrap();

                let update_resp = self
                    .process_message(
                        mcu_update_req.cmd_code().0,
                        mcu_update_req.as_bytes().unwrap(),
                    )
                    .map_err(|_| ())?;

                // Parse update response
                const UPDATE_HEADER_SIZE: usize =
                    core::mem::size_of::<CmAesGcmDecryptUpdateRespHeader>();
                let update_hdr = CmAesGcmDecryptUpdateRespHeader::read_from_bytes(
                    &update_resp.data[..UPDATE_HEADER_SIZE],
                )
                .map_err(|_| ())?;

                assert_eq!(
                    update_hdr.hdr.fips_status,
                    MailboxRespHeader::FIPS_STATUS_APPROVED,
                    "FIPS status should be approved"
                );
                assert_eq!(
                    update_hdr.plaintext_size as usize, chunk_len,
                    "Update plaintext size should match input size"
                );

                let pt_len = update_hdr.plaintext_size as usize;
                plaintext.extend_from_slice(
                    &update_resp.data[UPDATE_HEADER_SIZE..UPDATE_HEADER_SIZE + pt_len],
                );

                context = update_hdr.context;
                remaining = &remaining[chunk_len..];
            }

            // Final request with remaining ciphertext and tag
            let mut final_req = CmAesGcmDecryptFinalReq {
                hdr: MailboxReqHeader::default(),
                context,
                tag_len: 16,
                tag: *tag,
                ciphertext_size: remaining.len() as u32,
                ciphertext: [0u8; MAX_CMB_DATA_SIZE],
            };
            if !remaining.is_empty() {
                final_req.ciphertext[..remaining.len()].copy_from_slice(remaining);
            }

            let mut mcu_final_req =
                McuMailboxReq::AesGcmDecryptFinal(McuAesGcmDecryptFinalReq(final_req));
            mcu_final_req.populate_chksum().unwrap();

            let final_resp = self
                .process_message(
                    mcu_final_req.cmd_code().0,
                    mcu_final_req.as_bytes().unwrap(),
                )
                .map_err(|_| ())?;

            // Parse final response
            const FINAL_HEADER_SIZE: usize = core::mem::size_of::<CmAesGcmDecryptFinalRespHeader>();
            let final_hdr = CmAesGcmDecryptFinalRespHeader::read_from_bytes(
                &final_resp.data[..FINAL_HEADER_SIZE],
            )
            .map_err(|_| ())?;

            assert_eq!(
                final_hdr.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );
            assert_eq!(
                final_hdr.plaintext_size as usize,
                remaining.len(),
                "Final plaintext size should match input size"
            );

            let pt_len = final_hdr.plaintext_size as usize;
            plaintext
                .extend_from_slice(&final_resp.data[FINAL_HEADER_SIZE..FINAL_HEADER_SIZE + pt_len]);

            let tag_verified = final_hdr.tag_verified == 1;
            Ok((tag_verified, plaintext))
        }
    }
}
