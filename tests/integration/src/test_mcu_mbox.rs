// Licensed under the Apache-2.0 license

#[cfg(feature = "fpga_realtime")]
#[cfg(test)]
pub mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use aes_gcm::{aead::AeadMutInPlace, Aes256Gcm, Key, KeyInit};
    use caliptra_api::mailbox::CmHashAlgorithm;
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
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
        CmAesMode, CmAesRespHeader, CmDeleteReq, CmEcdhFinishReq, CmEcdhGenerateReq,
        CmEcdhGenerateResp, CmEcdsaPublicKeyReq, CmEcdsaSignReq, CmEcdsaVerifyReq, CmHkdfExpandReq,
        CmHkdfExtractReq, CmHmacKdfCounterReq, CmHmacReq, CmImportReq, CmKeyUsage,
        CmRandomGenerateReq, CmRandomStirReq, CmShaFinalReq, CmShaFinalResp, CmShaInitReq,
        CmShaUpdateReq, Cmk, DeviceCapsReq, DeviceCapsResp, DeviceIdReq, DeviceIdResp,
        DeviceInfoReq, DeviceInfoResp, FirmwareVersionReq, FirmwareVersionResp, MailboxReqHeader,
        MailboxRespHeader, MailboxRespHeaderVarSize, McuAesDecryptInitReq, McuAesDecryptUpdateReq,
        McuAesEncryptInitReq, McuAesEncryptUpdateReq, McuAesGcmDecryptFinalReq,
        McuAesGcmDecryptInitReq, McuAesGcmDecryptUpdateReq, McuAesGcmEncryptFinalReq,
        McuAesGcmEncryptInitReq, McuAesGcmEncryptUpdateReq, McuCmDeleteReq, McuCmImportReq,
        McuCmImportResp, McuCmStatusReq, McuCmStatusResp, McuEcdhFinishReq, McuEcdhFinishResp,
        McuEcdhGenerateReq, McuEcdhGenerateResp, McuEcdsaCmkPublicKeyReq, McuEcdsaCmkPublicKeyResp,
        McuEcdsaCmkSignReq, McuEcdsaCmkSignResp, McuEcdsaCmkVerifyReq, McuEcdsaCmkVerifyResp,
        McuFipsPeriodicEnableReq, McuFipsPeriodicStatusReq, McuFipsPeriodicStatusResp,
        McuFipsSelfTestGetResultsReq, McuFipsSelfTestStartReq, McuFipsSelfTestStartResp,
        McuHkdfExpandReq, McuHkdfExpandResp, McuHkdfExtractReq, McuHkdfExtractResp,
        McuHmacKdfCounterReq, McuHmacKdfCounterResp, McuHmacReq, McuMailboxReq, McuMailboxResp,
        McuRandomGenerateReq, McuRandomStirReq, McuShaFinalReq, McuShaFinalResp, McuShaInitReq,
        McuShaInitResp, McuShaUpdateReq, CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE,
        CMB_ECDH_EXCHANGE_DATA_MAX_SIZE, DEVICE_CAPS_SIZE, MAX_CMB_DATA_SIZE,
    };
    use mcu_testing_common::{
        emulator_ticks_elapsed, get_emulator_ticks, sleep_emulator_ticks, wait_for_runtime_start,
        MCU_RUNNING,
    };
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::ecdsa::{Signature, SigningKey};
    use rand::prelude::*;
    use rand::rngs::StdRng;
    use random_port::PortPicker;
    use registers_generated::mci;
    use sha2::{Digest, Sha384, Sha512};
    use std::process::exit;
    use std::sync::atomic::Ordering;
    use zerocopy::{FromBytes, IntoBytes};

    type HmacSha384 = Hmac<Sha384>;
    type HmacSha512 = Hmac<Sha512>;
    type Hkdf384 = Hkdf<Sha384>;
    type Hkdf512 = Hkdf<Sha512>;

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

    #[test]
    pub fn test_mcu_mbox_fips_self_test() {
        start_mcu_mbox_tests("test-mcu-mbox-fips-self-test");
    }

    #[test]
    pub fn test_mcu_mbox_fips_periodic() {
        start_mcu_mbox_tests("test-mcu-mbox-fips-periodic");
    }

    fn start_mcu_mbox_tests(feature: &str) {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
        let feature = feature.replace("_", "-");

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(&feature),
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            ..Default::default()
        });

        hw.start_i3c_controller();
        let mci_ptr = hw.base.mmio.mci().unwrap().ptr as u64;

        std::thread::spawn(move || {
            wait_for_runtime_start();
            if !MCU_RUNNING.load(Ordering::Relaxed) {
                exit(-1);
            }
            // Wait for firmware to initialize
            sleep_emulator_ticks(5_000_000);
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
            self.process_message_with_options(
                cmd, request, 20_000_000, // 20 seconds in emulator ticks
                false,
            )
        }

        /// Process a mailbox message with configurable timeout and error handling.
        ///
        /// # Arguments
        /// * `cmd` - The command code
        /// * `request` - The request payload
        /// * `timeout_ticks` - Maximum time to wait for a response in emulator ticks
        /// * `continue_on_error` - If true, continue polling on non-busy errors instead of returning immediately
        fn process_message_with_options(
            &mut self,
            cmd: u32,
            request: &[u8],
            timeout_ticks: u64,
            continue_on_error: bool,
        ) -> Result<McuMailboxResponse, McuMailboxError> {
            self.mbox.execute(cmd, request)?;

            let start = get_emulator_ticks();
            loop {
                match self.mbox.get_execute_response() {
                    Ok(resp) => return Ok(resp),
                    Err(McuMailboxError::Busy) => {
                        if emulator_ticks_elapsed(start, timeout_ticks) {
                            println!(
                                "Timeout waiting for response for MCU mailbox cmd: {:#X}",
                                cmd
                            );
                            return Err(McuMailboxError::Timeout);
                        }
                        sleep_emulator_ticks(100_000);
                    }
                    Err(e) => {
                        if continue_on_error {
                            if emulator_ticks_elapsed(start, timeout_ticks) {
                                println!(
                                    "Timeout waiting for response for MCU mailbox cmd: {:#X}",
                                    cmd
                                );
                                return Err(McuMailboxError::Timeout);
                            }
                            sleep_emulator_ticks(100_000);
                        } else {
                            return Err(e);
                        }
                    }
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
                self.add_ecdh_tests()?;
                self.add_ecdsa_tests()?;
                self.add_hmac_tests()?;
                self.add_hmac_kdf_counter_tests()?;
                self.add_hkdf_tests()?;
                Ok(())
            } else if feature == "test-mcu-mbox-fips-self-test" {
                self.add_fips_self_test_tests()?;
                Ok(())
            } else if feature == "test-mcu-mbox-fips-periodic" {
                self.add_fips_periodic_tests()?;
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

        /// Test ECDH key exchange operations.
        /// 1. Generate an ECDH key pair via the MCU mailbox
        /// 2. Generate a separate key pair using OpenSSL (simulating peer)
        /// 3. Compute shared secret on both sides
        /// 4. Verify by comparing AES-GCM encryption outputs
        fn add_ecdh_tests(&mut self) -> Result<(), ()> {
            println!("Running ECDH tests");

            // Step 1: Generate ECDH key pair via MCU mailbox
            let resp = self.ecdh_generate()?;
            println!("  Generated ECDH key pair via mailbox");

            // Step 2: Calculate our side of the exchange using OpenSSL
            // Based on the flow in https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
            let mut bn_ctx = openssl::bn::BigNumContext::new().unwrap();
            let curve =
                openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();

            // Parse the mailbox's public key (exchange_data is x||y coordinates)
            let mut a_exchange_data = vec![4]; // Uncompressed point format prefix
            a_exchange_data.extend_from_slice(&resp.exchange_data);
            let a_public_point =
                openssl::ec::EcPoint::from_bytes(&curve, &a_exchange_data, &mut bn_ctx).unwrap();
            let a_key = openssl::ec::EcKey::from_public_key(&curve, &a_public_point).unwrap();

            // Generate our own key pair
            let b_key = openssl::ec::EcKey::generate(&curve).unwrap();
            let b_exchange_data = &b_key
                .public_key()
                .to_bytes(
                    &curve,
                    openssl::ec::PointConversionForm::UNCOMPRESSED,
                    &mut bn_ctx,
                )
                .unwrap()[1..]; // Skip the 0x04 prefix

            // Derive the shared secret using OpenSSL
            let a_pkey = openssl::pkey::PKey::from_ec_key(a_key).unwrap();
            let b_pkey = openssl::pkey::PKey::from_ec_key(b_key).unwrap();
            let mut deriver = openssl::derive::Deriver::new(&b_pkey).unwrap();
            deriver.set_peer(&a_pkey).unwrap();
            let shared_secret = deriver.derive_to_vec().unwrap();
            println!("  Computed shared secret via OpenSSL");

            // Step 3: Calculate the shared secret using the MCU mailbox
            let mut send_exchange_data = [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE];
            send_exchange_data[..b_exchange_data.len()].copy_from_slice(b_exchange_data);
            let cmk = self.ecdh_finish(&resp, &send_exchange_data, CmKeyUsage::Aes)?;
            println!("  Derived shared key via mailbox");

            // Step 4: Verify by comparing AES-GCM encryption
            // Use the CMK to encrypt a known plaintext via mailbox
            let plaintext = [0u8; 16];
            let (iv, tag, ciphertext) = self.aes_gcm_encrypt(&cmk, &[], &plaintext)?;
            println!("  Encrypted test data via mailbox");

            // Encrypt the same plaintext using RustCrypto with OpenSSL-derived shared secret
            let (rtag, rciphertext) =
                rustcrypto_gcm_encrypt(&shared_secret[..32], &iv, &[], &plaintext);

            // Compare results - if they match, both sides derived the same shared secret
            assert_eq!(
                ciphertext, rciphertext,
                "Ciphertext should match between mailbox and OpenSSL"
            );
            assert_eq!(
                tag, rtag,
                "AES-GCM tag should match between mailbox and OpenSSL"
            );
            println!("  Verified: ciphertext and tags match!");

            // Clean up CMK created by ecdh_finish to avoid resource leaks
            self.delete_key(&cmk)?;

            println!("ECDH tests passed");
            Ok(())
        }

        /// Perform ECDH generate to create an ephemeral key pair.
        /// Returns the generate response containing context and exchange_data (public key).
        fn ecdh_generate(&mut self) -> Result<CmEcdhGenerateResp, ()> {
            let mut ecdh_generate_req =
                McuMailboxReq::EcdhGenerate(McuEcdhGenerateReq(CmEcdhGenerateReq {
                    hdr: MailboxReqHeader::default(),
                }));
            ecdh_generate_req.populate_chksum().unwrap();

            let resp = self
                .process_message(
                    ecdh_generate_req.cmd_code().0,
                    ecdh_generate_req.as_bytes().unwrap(),
                )
                .map_err(|_| ())?;

            let ecdh_resp = McuEcdhGenerateResp::read_from_bytes(&resp.data).map_err(|_| ())?;

            assert_eq!(
                ecdh_resp.0.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );

            Ok(ecdh_resp.0)
        }

        /// Perform ECDH finish to derive a shared secret key.
        /// Takes the generate response (containing context) and the peer's exchange data.
        /// Returns the derived key (Cmk).
        fn ecdh_finish(
            &mut self,
            generate_resp: &CmEcdhGenerateResp,
            incoming_exchange_data: &[u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
            key_usage: CmKeyUsage,
        ) -> Result<Cmk, ()> {
            let mut ecdh_finish_req =
                McuMailboxReq::EcdhFinish(McuEcdhFinishReq(CmEcdhFinishReq {
                    hdr: MailboxReqHeader::default(),
                    context: generate_resp.context,
                    key_usage: key_usage.into(),
                    incoming_exchange_data: *incoming_exchange_data,
                }));
            ecdh_finish_req.populate_chksum().unwrap();

            let resp = self
                .process_message(
                    ecdh_finish_req.cmd_code().0,
                    ecdh_finish_req.as_bytes().unwrap(),
                )
                .map_err(|_| ())?;

            let ecdh_finish_resp =
                McuEcdhFinishResp::read_from_bytes(&resp.data).map_err(|_| ())?;

            assert_eq!(
                ecdh_finish_resp.0.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );

            Ok(ecdh_finish_resp.0.output.clone())
        }

        /// Test ECDSA operations: public key extraction, sign, and verify.
        /// 1. Import an ECDSA key
        /// 2. Get the public key and verify it matches expected value
        /// 3. Sign random messages via mailbox
        /// 4. Verify signature matches RustCrypto ECDSA signature
        /// 5. Verify via mailbox with correct message (should succeed)
        /// 6. Verify via mailbox with modified message (should fail)
        fn add_ecdsa_tests(&mut self) -> Result<(), ()> {
            println!("Running ECDSA tests");

            // Import a 48-byte seed for ECDSA (P-384)
            let seed_bytes = [0u8; 48];
            let cmk = self.import_key(&seed_bytes, CmKeyUsage::Ecdsa)?;
            println!("  Imported ECDSA key");

            // Seed RNG for random test messages
            let seed_rng_bytes = [1u8; 32];
            let mut seeded_rng = StdRng::from_seed(seed_rng_bytes);

            // Private key corresponding to the imported seed (test vector from caliptra-sw)
            let privkey: [u8; 48] = [
                0xfe, 0xee, 0xf5, 0x54, 0x4a, 0x76, 0x56, 0x49, 0x90, 0x12, 0x8a, 0xd1, 0x89, 0xe8,
                0x73, 0xf2, 0x1f, 0xd, 0xfd, 0x5a, 0xd7, 0xe2, 0xfa, 0x86, 0x11, 0x27, 0xee, 0x6e,
                0x39, 0x4c, 0xa7, 0x84, 0x87, 0x1c, 0x1a, 0xec, 0x3, 0x2c, 0x7a, 0x8b, 0x10, 0xb9,
                0x3e, 0xe, 0xab, 0x89, 0x46, 0xd6,
            ];

            // Get public key
            let pub_key = self.ecdsa_public_key(&cmk)?;
            println!(
                "  Got public key: X[0..4]={:02x?}, Y[0..4]={:02x?}",
                &pub_key.0[..4],
                &pub_key.1[..4]
            );

            // Expected public key values (from deterministic seed of all zeros)
            let expected_pub_key_x: [u8; 48] = [
                0xd7, 0xdd, 0x94, 0xe0, 0xbf, 0xfc, 0x4c, 0xad, 0xe9, 0x90, 0x2b, 0x7f, 0xdb, 0x15,
                0x42, 0x60, 0xd5, 0xec, 0x5d, 0xfd, 0x57, 0x95, 0x0e, 0x83, 0x59, 0x01, 0x5a, 0x30,
                0x2c, 0x8b, 0xf7, 0xbb, 0xa7, 0xe5, 0xf6, 0xdf, 0xfc, 0x16, 0x85, 0x16, 0x2b, 0xdd,
                0x35, 0xf9, 0xf5, 0xc1, 0xb0, 0xff,
            ];
            let expected_pub_key_y: [u8; 48] = [
                0xbb, 0x9c, 0x3a, 0x2f, 0x06, 0x1e, 0x8d, 0x70, 0x14, 0x27, 0x8d, 0xd5, 0x1e, 0x66,
                0xa9, 0x18, 0xa6, 0xb6, 0xf9, 0xf1, 0xc1, 0x93, 0x73, 0x12, 0xd4, 0xe7, 0xa9, 0x21,
                0xb1, 0x8e, 0xf0, 0xf4, 0x1f, 0xdd, 0x40, 0x1d, 0x9e, 0x77, 0x18, 0x50, 0x9f, 0x87,
                0x31, 0xe9, 0xee, 0xc9, 0xc3, 0x1d,
            ];
            assert_eq!(pub_key.0, expected_pub_key_x, "Public key X should match");
            assert_eq!(pub_key.1, expected_pub_key_y, "Public key Y should match");

            // Test sign and verify with random messages (aligned with caliptra-sw approach)
            // Using fewer iterations than caliptra-sw (25) due to MCU test environment constraints
            for i in 0..10 {
                // Generate random message length and data
                let len = seeded_rng.gen_range(1..MAX_CMB_DATA_SIZE / 2);
                let mut data = vec![0u8; len];
                seeded_rng.fill_bytes(&mut data);

                println!(
                    "  Testing ECDSA sign/verify iteration {} with message length: {}",
                    i, len
                );

                // Sign the message via mailbox
                let signature = self.ecdsa_sign(&cmk, &data)?;
                println!(
                    "    Mailbox signed: R[0..4]={:02x?}, S[0..4]={:02x?}",
                    &signature.0[..4],
                    &signature.1[..4]
                );

                // Hash the message with SHA384 and sign with RustCrypto to verify
                let mut hasher = Sha384::new();
                hasher.update(&data);
                let hash = hasher.finalize();
                let hash_arr: [u8; 48] = hash.into();

                let rustcrypto_sig = rustcrypto_ecdsa_sign(&privkey, &hash_arr);
                println!(
                    "    RustCrypto signed: R[0..4]={:02x?}, S[0..4]={:02x?}",
                    &rustcrypto_sig.0[..4],
                    &rustcrypto_sig.1[..4]
                );

                // Verify signatures match between mailbox and RustCrypto
                assert_eq!(
                    signature.0, rustcrypto_sig.0,
                    "Signature R should match RustCrypto"
                );
                assert_eq!(
                    signature.1, rustcrypto_sig.1,
                    "Signature S should match RustCrypto"
                );
                println!("    Signatures match between mailbox and RustCrypto");

                // Verify via mailbox with correct message (should succeed)
                self.ecdsa_verify(&cmk, &data, &signature.0, &signature.1)?;
                println!("    Mailbox verification with correct message succeeded");

                // Verify with modified message (should fail)
                let mut modified_data = data.clone();
                let modify_idx = seeded_rng.gen_range(0..len);
                modified_data[modify_idx] ^= seeded_rng.gen_range(1..=255u8);

                let verify_fail_result =
                    self.ecdsa_verify(&cmk, &modified_data, &signature.0, &signature.1);
                assert!(
                    verify_fail_result.is_err(),
                    "Signature verification should fail with modified message"
                );
                println!("    Mailbox verification with modified message failed as expected");
            }

            // Clean up
            self.delete_key(&cmk)?;
            println!("ECDSA tests passed");
            Ok(())
        }

        /// Get the public key for an ECDSA CMK.
        fn ecdsa_public_key(&mut self, cmk: &Cmk) -> Result<([u8; 48], [u8; 48]), ()> {
            let mut req =
                McuMailboxReq::EcdsaCmkPublicKey(McuEcdsaCmkPublicKeyReq(CmEcdsaPublicKeyReq {
                    hdr: MailboxReqHeader::default(),
                    cmk: cmk.clone(),
                }));
            req.populate_chksum().unwrap();

            let resp = self
                .process_message(req.cmd_code().0, req.as_bytes().unwrap())
                .map_err(|_| ())?;

            let pub_key_resp =
                McuEcdsaCmkPublicKeyResp::read_from_bytes(&resp.data).map_err(|_| ())?;

            assert_eq!(
                pub_key_resp.0.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );

            Ok((pub_key_resp.0.public_key_x, pub_key_resp.0.public_key_y))
        }

        /// Sign a message using an ECDSA CMK.
        fn ecdsa_sign(&mut self, cmk: &Cmk, message: &[u8]) -> Result<([u8; 48], [u8; 48]), ()> {
            let mut sign_req = CmEcdsaSignReq {
                hdr: MailboxReqHeader::default(),
                cmk: cmk.clone(),
                message_size: message.len() as u32,
                ..Default::default()
            };
            sign_req.message[..message.len()].copy_from_slice(message);

            let mut req = McuMailboxReq::EcdsaCmkSign(McuEcdsaCmkSignReq(sign_req));
            req.populate_chksum().unwrap();

            let resp = self
                .process_message(req.cmd_code().0, req.as_bytes().unwrap())
                .map_err(|_| ())?;

            let sign_resp = McuEcdsaCmkSignResp::read_from_bytes(&resp.data).map_err(|_| ())?;

            assert_eq!(
                sign_resp.0.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );

            Ok((sign_resp.0.signature_r, sign_resp.0.signature_s))
        }

        /// Verify a signature using an ECDSA CMK.
        fn ecdsa_verify(
            &mut self,
            cmk: &Cmk,
            message: &[u8],
            signature_r: &[u8; 48],
            signature_s: &[u8; 48],
        ) -> Result<(), ()> {
            let mut verify_req = CmEcdsaVerifyReq {
                hdr: MailboxReqHeader::default(),
                cmk: cmk.clone(),
                signature_r: *signature_r,
                signature_s: *signature_s,
                message_size: message.len() as u32,
                ..Default::default()
            };
            verify_req.message[..message.len()].copy_from_slice(message);

            let mut req = McuMailboxReq::EcdsaCmkVerify(McuEcdsaCmkVerifyReq(verify_req));
            req.populate_chksum().unwrap();

            let result = self.process_message(req.cmd_code().0, req.as_bytes().unwrap());

            match result {
                Ok(resp) => {
                    let verify_resp =
                        McuEcdsaCmkVerifyResp::read_from_bytes(&resp.data).map_err(|_| ())?;
                    assert_eq!(
                        verify_resp.0.fips_status,
                        MailboxRespHeader::FIPS_STATUS_APPROVED,
                        "FIPS status should be approved"
                    );
                    Ok(())
                }
                Err(_) => Err(()), // Verification failed (signature mismatch)
            }
        }

        /// Test FIPS self-test start and get results commands.
        /// This test exercises the FIPS KAT (Known Answer Test) passthrough functionality.
        /// Follows the polling pattern from caliptra-sw's exec_cmd_self_test_get_results.
        fn add_fips_self_test_tests(&mut self) -> Result<(), ()> {
            println!("Running FIPS self-test tests");

            // Step 1: Start the FIPS self-test
            let mut self_test_start_req = McuMailboxReq::FipsSelfTestStart(
                McuFipsSelfTestStartReq(MailboxReqHeader::default()),
            );
            self_test_start_req.populate_chksum().unwrap();

            let start_resp = self
                .process_message(
                    self_test_start_req.cmd_code().0,
                    self_test_start_req.as_bytes().unwrap(),
                )
                .map_err(|_| ())?;

            let start_resp_parsed =
                McuFipsSelfTestStartResp::read_from_bytes(&start_resp.data).map_err(|_| ())?;
            assert_eq!(
                start_resp_parsed.0.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS self-test start should return approved status"
            );
            println!("  FIPS self-test started successfully");

            // Add a delay before polling for results
            sleep_emulator_ticks(500_000);

            println!("  Polling for FIPS self-test results...");

            // Step 2: Get the self-test results with extended timeout.
            // Caliptra runs the self-test during enter_idle() when the mailbox is unlocked.
            // Use continue_on_error=true to keep polling if the test isn't complete yet.
            let mut get_results_req = McuMailboxReq::FipsSelfTestGetResults(
                McuFipsSelfTestGetResultsReq(MailboxReqHeader::default()),
            );
            get_results_req.populate_chksum().unwrap();

            let _results_resp = self
                .process_message_with_options(
                    get_results_req.cmd_code().0,
                    get_results_req.as_bytes().unwrap(),
                    60_000_000, // 60 seconds in emulator ticks
                    true,
                )
                .map_err(|_| ())?;

            println!("FIPS self-test tests passed");
            Ok(())
        }

        /// Test periodic FIPS self-test enable/disable and status commands.
        fn add_fips_periodic_tests(&mut self) -> Result<(), ()> {
            println!("Running periodic FIPS self-test tests");

            // Step 1: Check initial status (should be disabled, 0 iterations)
            println!("  Checking initial status...");
            let mut status_req = McuMailboxReq::FipsPeriodicStatus(McuFipsPeriodicStatusReq(
                MailboxReqHeader::default(),
            ));
            status_req.populate_chksum().unwrap();

            let status_resp = self
                .process_message(status_req.cmd_code().0, status_req.as_bytes().unwrap())
                .map_err(|_| ())?;

            let status_parsed =
                McuFipsPeriodicStatusResp::read_from_bytes(&status_resp.data).map_err(|_| ())?;
            println!(
                "    Initial: enabled={}, iterations={}, last_result={}",
                status_parsed.enabled, status_parsed.iterations, status_parsed.last_result
            );
            assert_eq!(
                status_parsed.enabled, 0,
                "Periodic FIPS should be disabled initially"
            );
            assert_eq!(
                status_parsed.iterations, 0,
                "Should have 0 iterations initially"
            );

            // Step 2: Enable periodic FIPS self-test
            println!("  Enabling periodic FIPS self-test...");
            let mut enable_req = McuMailboxReq::FipsPeriodicEnable(McuFipsPeriodicEnableReq {
                header: MailboxReqHeader::default(),
                enable: 1,
            });
            enable_req.populate_chksum().unwrap();

            let _enable_resp = self
                .process_message(enable_req.cmd_code().0, enable_req.as_bytes().unwrap())
                .map_err(|_| ())?;
            println!("    Enabled successfully");

            // Step 3: Check status (should be enabled now)
            println!("  Checking status after enable...");
            let mut status_req2 = McuMailboxReq::FipsPeriodicStatus(McuFipsPeriodicStatusReq(
                MailboxReqHeader::default(),
            ));
            status_req2.populate_chksum().unwrap();

            let status_resp2 = self
                .process_message(status_req2.cmd_code().0, status_req2.as_bytes().unwrap())
                .map_err(|_| ())?;

            let status_parsed2 =
                McuFipsPeriodicStatusResp::read_from_bytes(&status_resp2.data).map_err(|_| ())?;
            println!(
                "    After enable: enabled={}, iterations={}, last_result={}",
                status_parsed2.enabled, status_parsed2.iterations, status_parsed2.last_result
            );
            assert_eq!(
                status_parsed2.enabled, 1,
                "Periodic FIPS should be enabled after enable command"
            );

            // Step 4: Disable periodic FIPS self-test
            println!("  Disabling periodic FIPS self-test...");
            let mut disable_req = McuMailboxReq::FipsPeriodicEnable(McuFipsPeriodicEnableReq {
                header: MailboxReqHeader::default(),
                enable: 0,
            });
            disable_req.populate_chksum().unwrap();

            let _disable_resp = self
                .process_message(disable_req.cmd_code().0, disable_req.as_bytes().unwrap())
                .map_err(|_| ())?;
            println!("    Disabled successfully");

            // Step 5: Check status (should be disabled now)
            println!("  Checking status after disable...");
            let mut status_req3 = McuMailboxReq::FipsPeriodicStatus(McuFipsPeriodicStatusReq(
                MailboxReqHeader::default(),
            ));
            status_req3.populate_chksum().unwrap();

            let status_resp3 = self
                .process_message(status_req3.cmd_code().0, status_req3.as_bytes().unwrap())
                .map_err(|_| ())?;

            let status_parsed3 =
                McuFipsPeriodicStatusResp::read_from_bytes(&status_resp3.data).map_err(|_| ())?;
            println!(
                "    After disable: enabled={}, iterations={}, last_result={}",
                status_parsed3.enabled, status_parsed3.iterations, status_parsed3.last_result
            );
            assert_eq!(
                status_parsed3.enabled, 0,
                "Periodic FIPS should be disabled after disable command"
            );

            println!("Periodic FIPS self-test tests passed");
            Ok(())
        }

        /// Test HMAC command.
        fn add_hmac_tests(&mut self) -> Result<(), ()> {
            println!("Running HMAC tests");

            // Seed RNG for random test data
            let seed_bytes = [1u8; 32];
            let mut seeded_rng = StdRng::from_seed(seed_bytes);

            // Test with both SHA384 (48-byte key) and SHA512 (64-byte key)
            for size in [48, 64] {
                let hash_algorithm = if size == 48 {
                    CmHashAlgorithm::Sha384
                } else {
                    CmHashAlgorithm::Sha512
                };
                println!(
                    "  Testing HMAC with {:?} (key size: {})",
                    hash_algorithm, size
                );

                // Import a key for HMAC
                let mut key = vec![0u8; size];
                seeded_rng.fill_bytes(&mut key);
                let cmk = self.import_key(&key, CmKeyUsage::Hmac)?;
                println!("    Imported HMAC key");

                // Test with multiple random messages
                for i in 0..5 {
                    let len = seeded_rng.gen_range(1..MAX_CMB_DATA_SIZE / 2);
                    let mut data = vec![0u8; len];
                    seeded_rng.fill_bytes(&mut data);

                    println!(
                        "    Testing HMAC iteration {} with message length: {}",
                        i, len
                    );

                    // Compute HMAC via mailbox
                    let mac = self.hmac(&cmk, hash_algorithm, &data)?;
                    println!("      Mailbox MAC[0..4]={:02x?}", &mac[..4.min(mac.len())]);

                    // Compute HMAC with RustCrypto and verify
                    let expected_mac = rustcrypto_hmac(hash_algorithm, &key, &data);
                    assert_eq!(mac.len(), expected_mac.len(), "MAC length should match");
                    assert_eq!(
                        mac, expected_mac,
                        "HMAC should match RustCrypto computation"
                    );
                    println!("      HMAC matches RustCrypto");
                }

                // Clean up
                self.delete_key(&cmk)?;
            }

            println!("HMAC tests passed");
            Ok(())
        }

        /// Compute HMAC using the mailbox API.
        fn hmac(
            &mut self,
            cmk: &Cmk,
            hash_algorithm: CmHashAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, ()> {
            let mut hmac_req = CmHmacReq {
                hdr: MailboxReqHeader::default(),
                cmk: cmk.clone(),
                hash_algorithm: hash_algorithm.into(),
                data_size: data.len() as u32,
                ..Default::default()
            };
            hmac_req.data[..data.len()].copy_from_slice(data);

            let mut req = McuMailboxReq::Hmac(McuHmacReq(hmac_req));
            req.populate_chksum().unwrap();

            let resp = self
                .process_message(req.cmd_code().0, req.as_bytes().unwrap())
                .map_err(|_| ())?;

            // Parse response header to get MAC size
            let hdr_size = core::mem::size_of::<MailboxRespHeaderVarSize>();
            let hdr = MailboxRespHeaderVarSize::read_from_bytes(&resp.data[..hdr_size])
                .map_err(|_| ())?;
            assert_eq!(
                hdr.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );

            let mac_len = hdr.data_len as usize;
            let mac = resp.data[hdr_size..hdr_size + mac_len].to_vec();
            Ok(mac)
        }

        /// Test HMAC KDF Counter command.
        fn add_hmac_kdf_counter_tests(&mut self) -> Result<(), ()> {
            println!("Running HMAC KDF Counter tests");

            // Seed RNG for random test data
            let seed_bytes = [1u8; 32];
            let mut seeded_rng = StdRng::from_seed(seed_bytes);

            // Test with both SHA384 (48-byte key) and SHA512 (64-byte key)
            for size in [48, 64] {
                let hash_algorithm = if size == 48 {
                    CmHashAlgorithm::Sha384
                } else {
                    CmHashAlgorithm::Sha512
                };
                println!(
                    "  Testing HMAC KDF Counter with {:?} (key size: {})",
                    hash_algorithm, size
                );

                // Import a key for HMAC
                let mut key = vec![0u8; size];
                seeded_rng.fill_bytes(&mut key);
                let cmk = self.import_key(&key, CmKeyUsage::Hmac)?;
                println!("    Imported HMAC key for KDF");

                // Test with multiple random labels
                for i in 0..5 {
                    let len = seeded_rng.gen_range(1..MAX_CMB_DATA_SIZE / 2);
                    let mut label = vec![0u8; len];
                    seeded_rng.fill_bytes(&mut label);

                    println!(
                        "    Testing HMAC KDF Counter iteration {} with label length: {}",
                        i, len
                    );

                    // Derive key via mailbox
                    let derived_cmk =
                        self.hmac_kdf_counter(&cmk, hash_algorithm, CmKeyUsage::Aes, 32, &label)?;
                    println!("      Got derived CMK");

                    // Compute expected derived key using RustCrypto
                    let expected_key = rustcrypto_hmac_kdf_counter(hash_algorithm, &key, &label);
                    println!(
                        "      Expected key[0..4]={:02x?}",
                        &expected_key[..4.min(expected_key.len())]
                    );

                    // Verify by encrypting with AES-GCM and comparing
                    let plaintext = [0u8; 16];
                    let (iv, tag, ciphertext) =
                        self.aes_gcm_encrypt(&derived_cmk, &[], &plaintext)?;

                    // expected_key is already truncated to 32 bytes by rustcrypto_hmac_kdf_counter
                    let (rtag, rciphertext) =
                        rustcrypto_gcm_encrypt(&expected_key, &iv, &[], &plaintext);

                    assert_eq!(
                        ciphertext, rciphertext,
                        "Ciphertext should match RustCrypto"
                    );
                    assert_eq!(tag, rtag, "Tag should match RustCrypto");
                    println!("      Derived key verified via AES-GCM encryption");

                    // Clean up derived key
                    self.delete_key(&derived_cmk)?;
                }

                // Clean up input key
                self.delete_key(&cmk)?;
            }

            println!("HMAC KDF Counter tests passed");
            Ok(())
        }

        /// Derive a key using HMAC KDF Counter.
        fn hmac_kdf_counter(
            &mut self,
            kin: &Cmk,
            hash_algorithm: CmHashAlgorithm,
            key_usage: CmKeyUsage,
            key_size: u32,
            label: &[u8],
        ) -> Result<Cmk, ()> {
            let mut kdf_req = CmHmacKdfCounterReq {
                hdr: MailboxReqHeader::default(),
                kin: kin.clone(),
                hash_algorithm: hash_algorithm.into(),
                key_usage: key_usage.into(),
                key_size,
                label_size: label.len() as u32,
                ..Default::default()
            };
            kdf_req.label[..label.len()].copy_from_slice(label);

            let mut req = McuMailboxReq::HmacKdfCounter(McuHmacKdfCounterReq(kdf_req));
            req.populate_chksum().unwrap();

            let resp = self
                .process_message(req.cmd_code().0, req.as_bytes().unwrap())
                .map_err(|_| ())?;

            let kdf_resp = McuHmacKdfCounterResp::read_from_bytes(&resp.data).map_err(|_| ())?;
            assert_eq!(
                kdf_resp.0.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );

            Ok(kdf_resp.0.kout)
        }

        /// Test HKDF Extract and Expand commands.
        fn add_hkdf_tests(&mut self) -> Result<(), ()> {
            println!("Running HKDF tests");

            // Seed RNG for random test data
            let seed_bytes = [1u8; 32];
            let mut seeded_rng = StdRng::from_seed(seed_bytes);

            // Test with both SHA384 (48-byte key) and SHA512 (64-byte key)
            for size in [48, 64] {
                let hash_algorithm = if size == 48 {
                    CmHashAlgorithm::Sha384
                } else {
                    CmHashAlgorithm::Sha512
                };
                println!(
                    "  Testing HKDF with {:?} (key size: {})",
                    hash_algorithm, size
                );

                // Import IKM (input keying material)
                let mut ikm = vec![0u8; size];
                seeded_rng.fill_bytes(&mut ikm);
                let ikm_cmk = self.import_key(&ikm, CmKeyUsage::Hmac)?;
                println!("    Imported IKM");

                // Test with multiple iterations
                for i in 0..5 {
                    // Generate random salt
                    let salt_len = seeded_rng.gen_range(0..size);
                    let mut salt = vec![0u8; size]; // Salt CMK must be full size
                    seeded_rng.fill_bytes(&mut salt[..salt_len]);

                    // Import salt as CMK
                    let salt_cmk = self.import_key(&salt, CmKeyUsage::Hmac)?;

                    // HKDF Extract
                    let prk_cmk = self.hkdf_extract(&ikm_cmk, &salt_cmk, hash_algorithm)?;
                    println!(
                        "    Iteration {}: Extracted PRK with salt length {}",
                        i, salt_len
                    );

                    // Generate random info
                    let info_len = seeded_rng.gen_range(0..MAX_CMB_DATA_SIZE / 2);
                    let mut info = vec![0u8; info_len];
                    seeded_rng.fill_bytes(&mut info);

                    // HKDF Expand
                    let okm_cmk =
                        self.hkdf_expand(&prk_cmk, hash_algorithm, CmKeyUsage::Aes, 32, &info)?;
                    println!(
                        "    Iteration {}: Expanded OKM with info length {}",
                        i, info_len
                    );

                    // Compute expected OKM using RustCrypto
                    // Use full salt buffer since CMK is imported with the complete buffer (including zero padding)
                    let expected_okm = rustcrypto_hkdf(hash_algorithm, &ikm, &salt, &info, 32);
                    println!(
                        "      Expected OKM[0..4]={:02x?}",
                        &expected_okm[..4.min(expected_okm.len())]
                    );

                    // Verify by encrypting with AES-GCM and comparing
                    let plaintext = [0u8; 16];
                    let (iv, tag, ciphertext) = self.aes_gcm_encrypt(&okm_cmk, &[], &plaintext)?;

                    // expected_okm is already 32 bytes as specified in rustcrypto_hkdf call
                    let (rtag, rciphertext) =
                        rustcrypto_gcm_encrypt(&expected_okm, &iv, &[], &plaintext);

                    assert_eq!(
                        ciphertext, rciphertext,
                        "Ciphertext should match RustCrypto"
                    );
                    assert_eq!(tag, rtag, "Tag should match RustCrypto");
                    println!("      Derived key verified via AES-GCM encryption");

                    // Clean up
                    self.delete_key(&okm_cmk)?;
                    self.delete_key(&prk_cmk)?;
                    self.delete_key(&salt_cmk)?;
                }

                // Clean up IKM
                self.delete_key(&ikm_cmk)?;
            }

            println!("HKDF tests passed");
            Ok(())
        }

        /// Perform HKDF Extract.
        fn hkdf_extract(
            &mut self,
            ikm: &Cmk,
            salt: &Cmk,
            hash_algorithm: CmHashAlgorithm,
        ) -> Result<Cmk, ()> {
            let extract_req = CmHkdfExtractReq {
                hdr: MailboxReqHeader::default(),
                hash_algorithm: hash_algorithm.into(),
                salt: salt.clone(),
                ikm: ikm.clone(),
            };

            let mut req = McuMailboxReq::HkdfExtract(McuHkdfExtractReq(extract_req));
            req.populate_chksum().unwrap();

            let resp = self
                .process_message(req.cmd_code().0, req.as_bytes().unwrap())
                .map_err(|_| ())?;

            let extract_resp = McuHkdfExtractResp::read_from_bytes(&resp.data).map_err(|_| ())?;
            assert_eq!(
                extract_resp.0.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );

            Ok(extract_resp.0.prk)
        }

        /// Perform HKDF Expand.
        fn hkdf_expand(
            &mut self,
            prk: &Cmk,
            hash_algorithm: CmHashAlgorithm,
            key_usage: CmKeyUsage,
            key_size: u32,
            info: &[u8],
        ) -> Result<Cmk, ()> {
            let mut expand_req = CmHkdfExpandReq {
                hdr: MailboxReqHeader::default(),
                prk: prk.clone(),
                hash_algorithm: hash_algorithm.into(),
                key_usage: key_usage.into(),
                key_size,
                info_size: info.len() as u32,
                ..Default::default()
            };
            expand_req.info[..info.len()].copy_from_slice(info);

            let mut req = McuMailboxReq::HkdfExpand(McuHkdfExpandReq(expand_req));
            req.populate_chksum().unwrap();

            let resp = self
                .process_message(req.cmd_code().0, req.as_bytes().unwrap())
                .map_err(|_| ())?;

            let expand_resp = McuHkdfExpandResp::read_from_bytes(&resp.data).map_err(|_| ())?;
            assert_eq!(
                expand_resp.0.hdr.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED,
                "FIPS status should be approved"
            );

            Ok(expand_resp.0.okm)
        }
    }

    /// Helper function to perform ECDSA signing using RustCrypto.
    /// Used for verifying signatures match between mailbox and RustCrypto.
    fn rustcrypto_ecdsa_sign(priv_key: &[u8; 48], hash: &[u8; 48]) -> ([u8; 48], [u8; 48]) {
        let signing_key = SigningKey::from_slice(priv_key).unwrap();
        let ecc_sig: Signature = signing_key.sign_prehash(hash).unwrap();
        let ecc_sig = ecc_sig.to_vec();
        let r = ecc_sig[..48].try_into().unwrap();
        let s = ecc_sig[48..].try_into().unwrap();
        (r, s)
    }

    /// Helper function to perform AES-GCM encryption using RustCrypto.
    /// Used for verifying shared secrets derived via ECDH.
    fn rustcrypto_gcm_encrypt(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> ([u8; 16], Vec<u8>) {
        let key: &Key<Aes256Gcm> = key.into();
        let mut cipher = Aes256Gcm::new(key);
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(iv.into(), aad, &mut buffer)
            .expect("Encryption failed");
        (tag.into(), buffer)
    }

    /// Helper function to compute HMAC using RustCrypto.
    fn rustcrypto_hmac(hash_algorithm: CmHashAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
        match hash_algorithm {
            CmHashAlgorithm::Sha384 => {
                let mut mac = <HmacSha384 as KeyInit>::new_from_slice(key).unwrap();
                mac.update(data);
                let result = mac.finalize();
                let x: [u8; 48] = result.into_bytes().into();
                x.into()
            }
            CmHashAlgorithm::Sha512 => {
                let mut mac = <HmacSha512 as KeyInit>::new_from_slice(key).unwrap();
                mac.update(data);
                let result = mac.finalize();
                let x: [u8; 64] = result.into_bytes().into();
                x.into()
            }
            _ => panic!("Invalid hash algorithm"),
        }
    }

    /// Helper function to compute HMAC KDF Counter using RustCrypto.
    fn rustcrypto_hmac_kdf_counter(
        hash_algorithm: CmHashAlgorithm,
        key: &[u8],
        label: &[u8],
    ) -> Vec<u8> {
        // Counter-mode KDF: HMAC(key, counter || label), then truncate to 32 bytes
        let mut data = vec![];
        data.extend(1u32.to_be_bytes().as_slice());
        data.extend(label);
        let mut okm = rustcrypto_hmac(hash_algorithm, key, &data);
        // Derive a 256-bit key (32 bytes) as used by AES-256-GCM in these tests.
        if okm.len() > 32 {
            okm.truncate(32);
        }
        okm
    }

    /// Helper function to compute HKDF using RustCrypto with a configurable output length.
    fn rustcrypto_hkdf(
        hash_algorithm: CmHashAlgorithm,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        key_size: usize,
    ) -> Vec<u8> {
        match hash_algorithm {
            CmHashAlgorithm::Sha384 => {
                let hk = Hkdf384::new(Some(salt), ikm);
                let mut okm = vec![0u8; key_size];
                hk.expand(info, &mut okm).unwrap();
                okm
            }
            CmHashAlgorithm::Sha512 => {
                let hk = Hkdf512::new(Some(salt), ikm);
                let mut okm = vec![0u8; key_size];
                hk.expand(info, &mut okm).unwrap();
                okm
            }
            _ => panic!("Invalid hash algorithm"),
        }
    }
}
