//! Licensed under the Apache-2.0 license

//! This module executes SPDM Responder conformance tests

#[cfg(test)]
mod test {
    use crate::test::{
        finish_runtime_hw_model, run_imaginary_flash_controller_service, start_runtime_hw_model,
        TestParams, TEST_LOCK,
    };
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
    use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
    use caliptra_mcu_testing_common::spdm_responder_validator::mctp::MctpTransport;
    use caliptra_mcu_testing_common::spdm_responder_validator::{
        execute_spdm_responder_validator, SpdmValidatorRunner, SERVER_LISTENING,
    };
    use caliptra_mcu_testing_common::{
        wait_for_runtime_start, wait_for_spdm_responder_ready, SpdmResponderTransport,
    };
    use random_port::PortPicker;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    const TEST_NAME: &str = "MCTP-SPDM-RESPONDER-VALIDATOR";

    /// Exercise the normal SPDM responder over the controller transport on both backends.
    /// Deterministic descriptor-pop/notification behaviour is covered by the I3C unit tests.
    #[test]
    fn test_mctp_spdm_fragmented_negotiate_algorithms() {
        use caliptra_mcu_spdm_codec::{
            AlgorithmsRspBodyFixed, AsymAlgos, CapFlags, CapabilitiesBody, HashAlgos, MeasSpec,
            NegotiateAlgorithmsReqBodyFixed, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion,
        };
        use caliptra_mcu_testing_common::mctp_util::base_protocol::MctpMsgType;
        use caliptra_mcu_testing_common::spdm_responder_validator::mctp::{
            MCTP_I3C_DEFAULT_PACKET_SIZE, MCTP_I3C_MIN_PACKET_SIZE,
        };
        use caliptra_mcu_testing_common::spdm_responder_validator::Transport;
        use std::time::Instant;
        use zerocopy::{little_endian::U16, FromBytes, Immutable, IntoBytes};

        // Extended algorithm entries have no codec type yet. Describe their wire
        // fields rather than indexing bytes in the NEGOTIATE_ALGORITHMS request.
        #[derive(IntoBytes, Immutable)]
        #[repr(C)]
        struct ExtendedAsymOffer {
            registry_id: u8,
            reserved: u8,
            algorithm_id: U16,
        }

        fn exchange(
            transport: &mut MctpTransport,
            version: SpdmVersion,
            request_code: ReqRespCode,
            body: &[u8],
            response_code: ReqRespCode,
        ) -> Vec<u8> {
            let request = [
                &[MctpMsgType::Spdm as u8],
                SpdmMsgHdrPdu::new(version, request_code).as_bytes(),
                body,
            ]
            .concat();
            let response = transport
                .target_send_and_receive(&request, false)
                .expect("SPDM responder did not reply");
            let (message_type, spdm) = response.split_first().unwrap();
            assert_eq!(*message_type, MctpMsgType::Spdm as u8);
            let (header, body) = SpdmMsgHdrPdu::read_from_prefix(spdm).unwrap();
            assert_eq!(header.version, version.to_u8());
            assert_eq!(header.code, response_code);
            body.to_vec()
        }

        let lock = TEST_LOCK.lock().unwrap();
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-mctp-spdm-responder-conformance"),
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            use_strap_secrets: true,
            ..Default::default()
        });
        hw.start_i3c_controller();
        run_imaginary_flash_controller_service(&mut hw);
        let addr = hw.i3c_address().unwrap();
        let stream =
            BufferedStream::new(TcpStream::connect(("127.0.0.1", hw.i3c_port().unwrap())).unwrap());
        let worker = caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
            wait_for_spdm_responder_ready(SpdmResponderTransport::Mctp);

            // Unsupported extended offers grow an otherwise ordinary request past
            // the baseline packet size. Counts and lengths follow the wire types.
            let fixed_len = SpdmMsgHdrPdu::SIZE + NegotiateAlgorithmsReqBodyFixed::SIZE;
            let offer_count = (MCTP_I3C_MIN_PACKET_SIZE - fixed_len)
                .div_ceil(std::mem::size_of::<ExtendedAsymOffer>());
            let offers: Vec<_> = (1..=offer_count)
                .map(|id| ExtendedAsymOffer {
                    registry_id: 0, // DMTF registry.
                    reserved: 0,
                    algorithm_id: (id as u16).into(),
                })
                .collect();
            let fixed = NegotiateAlgorithmsReqBodyFixed {
                length: ((fixed_len + offers.as_slice().as_bytes().len()) as u16).into(),
                measurement_spec: MeasSpec::DMTF,
                base_asym_algo: AsymAlgos::ECDSA_ECC_NIST_P384,
                base_hash_algo: HashAlgos::SHA_384,
                ext_asym_count: offers.len() as u8,
                ..Default::default()
            };
            let algorithms = [fixed.as_bytes(), offers.as_slice().as_bytes()].concat();
            let capabilities = CapabilitiesBody {
                flags: CapFlags::CERT,
                data_transfer_size: (NegotiateAlgorithmsReqBodyFixed::MAX_REQUEST_LENGTH as u32)
                    .into(),
                max_spdm_msg_size: (NegotiateAlgorithmsReqBodyFixed::MAX_REQUEST_LENGTH as u32)
                    .into(),
                ..Default::default()
            };
            for packet_size in [MCTP_I3C_DEFAULT_PACKET_SIZE, MCTP_I3C_MIN_PACKET_SIZE] {
                // No retries: a lost fragment must fail the test, not be hidden.
                let mut transport = MctpTransport::new_with_max_packet_size(
                    stream.try_clone().unwrap(),
                    addr,
                    0,
                    packet_size,
                );
                exchange(
                    &mut transport,
                    SpdmVersion::V10,
                    ReqRespCode::GET_VERSION,
                    &[0, 0],
                    ReqRespCode::VERSION,
                );
                exchange(
                    &mut transport,
                    SpdmVersion::V12,
                    ReqRespCode::GET_CAPABILITIES,
                    capabilities.as_bytes(),
                    ReqRespCode::CAPABILITIES,
                );
                let response = exchange(
                    &mut transport,
                    SpdmVersion::V12,
                    ReqRespCode::NEGOTIATE_ALGORITHMS,
                    &algorithms,
                    ReqRespCode::ALGORITHMS,
                );
                let (selected, _) = AlgorithmsRspBodyFixed::read_from_prefix(&response).unwrap();
                assert_eq!(
                    selected.base_asym_sel.into_bits(),
                    AsymAlgos::ECDSA_ECC_NIST_P384.into_bits()
                );
                assert_eq!(
                    selected.base_hash_sel.into_bits(),
                    HashAlgos::SHA_384.into_bits()
                );
            }
        });
        let start = Instant::now();
        const TEST_TIMEOUT: Duration = Duration::from_secs(180);
        hw.step_until(|hw| {
            assert!(
                start.elapsed() < TEST_TIMEOUT,
                "SPDM fragmentation test timed out"
            );
            assert_eq!(hw.mci_fw_fatal_error(), None);
            worker.is_finished()
        });
        worker.join().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn test_mctp_spdm_responder_conformance() {
        if std::env::var("SPDM_VALIDATOR_DIR").is_err() {
            println!("SPDM_VALIDATOR_DIR environment variable is not set. Skipping test");
            return;
        }

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-mctp-spdm-responder-conformance"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            use_strap_secrets: true,
            ..Default::default()
        });

        hw.start_i3c_controller();

        run_imaginary_flash_controller_service(&mut hw);

        let conformance_result = run_mctp_spdm_conformance_test(
            hw.i3c_port().unwrap(),
            hw.i3c_address().unwrap().into(),
            Duration::from_secs(9000), // timeout in seconds
        );

        let test = finish_runtime_hw_model(&mut hw);
        let conformance_result = conformance_result
            .recv_timeout(Duration::from_secs(10))
            .expect("SPDM conformance worker did not report a result");

        assert_eq!(0, test);
        conformance_result.expect("SPDM responder conformance failed");

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn run_mctp_spdm_conformance_test(
        port: u16,
        target_addr: DynamicI3cAddress,
        test_timeout: Duration,
    ) -> Receiver<Result<(), String>> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr).unwrap();
        let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);
        let (result_tx, result_rx) = mpsc::channel();
        let (timeout_cancel_tx, timeout_cancel_rx) = mpsc::channel();

        let timeout_result_tx = result_tx.clone();
        caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
            if timeout_cancel_rx.recv_timeout(test_timeout).is_err() {
                let message = format!(
                    "{TEST_NAME} timed out after {} seconds",
                    test_timeout.as_secs()
                );
                println!("[{TEST_NAME}] {message}");
                let _ = timeout_result_tx.send(Err(message));
                caliptra_mcu_testing_common::stop_emulator();
            }
        });

        SERVER_LISTENING.store(false, Ordering::Relaxed);
        let validator = execute_spdm_responder_validator("MCTP");
        caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
            wait_for_runtime_start();
            if !caliptra_mcu_testing_common::is_emulator_running() {
                return;
            }
            wait_for_spdm_responder_ready(SpdmResponderTransport::Mctp);
            if !caliptra_mcu_testing_common::is_emulator_running() {
                return;
            }

            let result = (|| -> Result<(), String> {
                let listener = TcpListener::bind("127.0.0.1:2323")
                    .map_err(|err| format!("could not bind SPDM listener: {err}"))?;
                println!("[{TEST_NAME}]: SPDM server listening on port 2323");
                SERVER_LISTENING.store(true, Ordering::Relaxed);

                let (mut spdm_stream, _) = listener
                    .accept()
                    .map_err(|err| format!("failed to accept SPDM connection: {err}"))?;
                let mut test = SpdmValidatorRunner::new(Box::new(transport), TEST_NAME);
                test.run_test(&mut spdm_stream);

                let validator_passed = validator
                    .join()
                    .map_err(|_| "SPDM validator worker panicked".to_string())?;
                if !test.is_passed() {
                    return Err("SPDM transport bridge failed".to_string());
                }
                if !validator_passed {
                    return Err("SPDM validator exited unsuccessfully".to_string());
                }

                println!("[{TEST_NAME}]: SPDM responder conformance passed");
                Ok(())
            })();

            let _ = timeout_cancel_tx.send(());
            let _ = result_tx.send(result);
            caliptra_mcu_testing_common::stop_emulator();
        });

        result_rx
    }
}
