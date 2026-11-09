// Licensed under the Apache-2.0 license

//! Emulator-only driver fault and Linux I3C receive-contract tests.
//! These run real MCU firmware, not the Linux driver or electrical I3C.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_emulator_periph::{I3cIbiOutcome, I3cIbiStatus, I3cTarget};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
    use caliptra_mcu_testing_common::mctp_util::base_protocol::{
        MCTPHdr, MctpMsgType, LOCAL_TEST_ENDPOINT_EID, MCTP_HDR_SIZE,
    };
    use caliptra_mcu_testing_common::mctp_util::ctrl_protocol::{
        generate_msg_type_support_resp_bytes, get_eid_resp_bytes, get_endpoint_uuid_resp_bytes,
        get_version_support_resp_bytes, set_eid_req_bytes, set_eid_resp_bytes, CmdCompletionCode,
        MCTPCtrlCmd, MCTPCtrlMsgHdr, SetEIDAllocStatus, SetEIDOp, SetEIDStatus, VersionEntry,
    };
    use caliptra_mcu_testing_common::{
        emulator_ticks_elapsed, get_emulator_ticks, is_emulator_running, sleep_emulator_ticks,
        spawn_with_emulator_state, stop_emulator,
    };
    use random_port::PortPicker;
    use std::net::{SocketAddr, TcpStream};
    use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
    use std::sync::atomic::Ordering;
    use zerocopy::{FromBytes, IntoBytes};

    const TEST_TIMEOUT: u64 = 30_000_000;
    const RESPONSE_TIMEOUT: u64 = 5_000_000;
    const LINUX_MAX_IBI_PAYLOAD: usize = 1;
    const MCTP_MRL: u16 = 256;

    fn wait_for<T>(mut read: impl FnMut() -> Option<T>) -> T {
        let start = get_emulator_ticks();
        loop {
            if let Some(value) = read() {
                return value;
            }
            assert!(is_emulator_running(), "firmware stopped before response");
            assert!(
                !emulator_ticks_elapsed(start, RESPONSE_TIMEOUT),
                "I3C response timeout"
            );
            sleep_emulator_ticks(10_000);
        }
    }

    fn assert_silent(stream: &mut BufferedStream, addr: u8) {
        sleep_emulator_ticks(200_000);
        assert!(stream.receive_ibi_packet(addr).is_none());
        assert!(stream.receive_private_read_raw(addr).is_none());
    }

    fn linux_read_packet(stream: &mut BufferedStream, addr: u8, mrl: u16) -> Option<Vec<u8>> {
        let (mdb, payload) = wait_for(|| stream.receive_ibi_packet(addr));
        if 1 + payload.len() > LINUX_MAX_IBI_PAYLOAD || mdb != 0xae {
            return None;
        }
        stream.send_private_read_request_with_len(addr, mrl);
        let packet = wait_for(|| stream.receive_private_read_raw(addr));
        assert!((5..=usize::from(mrl)).contains(&packet.len()));
        let (&received_pec, data) = packet.split_last().unwrap();
        let pec = data.iter().fold(
            caliptra_mcu_romtime::crc8(0, (addr << 1) | 1),
            |crc, byte| caliptra_mcu_romtime::crc8(crc, *byte),
        );
        assert_eq!(received_pec, pec);
        Some(data.to_vec())
    }

    fn linux_control_exchange(
        stream: &mut BufferedStream,
        addr: u8,
        destination_eid: u8,
        response_eid: u8,
        instance_id: u8,
        command: MCTPCtrlCmd,
        request_data: &[u8],
    ) -> Vec<u8> {
        let tag = instance_id & 7;
        let mut header = MCTPHdr::new();
        header.prepare_header(destination_eid, LOCAL_TEST_ENDPOINT_EID, 1, 1, 0, 1, tag);
        let mut control = MCTPCtrlMsgHdr::new();
        control.set_rq(1);
        control.set_instance_id(instance_id);
        control.set_cmd(command as u8);
        let mut request = header.as_bytes().to_vec();
        request.push(MctpMsgType::Ctrl as u8);
        request.extend_from_slice(control.as_bytes());
        request.extend_from_slice(request_data);
        assert!(stream.send_private_write(addr, request));

        let response = linux_read_packet(stream, addr, MCTP_MRL)
            .expect("Linux controller rejected the pending-read IBI");
        assert!(response.len() >= MCTP_HDR_SIZE + 4);
        assert!(response.len() + 1 < usize::from(MCTP_MRL));
        let response_header =
            MCTPHdr::<[u8; MCTP_HDR_SIZE]>::read_from_bytes(&response[..MCTP_HDR_SIZE]).unwrap();
        header.prepare_header(LOCAL_TEST_ENDPOINT_EID, response_eid, 1, 1, 0, 0, tag);
        assert_eq!(response_header, header);
        assert_eq!(response[MCTP_HDR_SIZE], MctpMsgType::Ctrl as u8);
        control.set_rq(0);
        assert_eq!(
            &response[MCTP_HDR_SIZE + 1..MCTP_HDR_SIZE + 3],
            control.as_bytes()
        );
        assert_silent(stream, addr);
        response[MCTP_HDR_SIZE + 3..].to_vec()
    }

    fn echo(stream: &mut BufferedStream, addr: u8, payload: Vec<u8>) {
        assert!(stream.send_private_write(addr, payload.clone()));
        let (mdb, ibi) = wait_for(|| stream.receive_ibi_packet(addr));
        assert_eq!(mdb, 0xae);
        assert_eq!(ibi, ((payload.len() + 1) as u16).to_be_bytes());
        // TX is queued and the IBI has succeeded, but no data may be forwarded
        // until the controller explicitly reads it.
        assert_silent(stream, addr);
        stream.send_private_read_request_with_len(addr, (payload.len() + 1) as u16);
        let response = wait_for(|| stream.receive_private_read(addr));
        assert_eq!(response, payload);
        assert_silent(stream, addr);
    }

    fn run_echo_test(scenario: impl FnOnce(&mut BufferedStream, u8, I3cTarget) + Send + 'static) {
        run_i3c_test("test-i3c-echo", "I3C echo ready", scenario);
    }

    fn run_i3c_test(
        feature: &str,
        ready: &str,
        scenario: impl FnOnce(&mut BufferedStream, u8, I3cTarget) + Send + 'static,
    ) {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(feature),
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            ..Default::default()
        });
        hw.start_i3c_controller();
        let start = hw.cycle_count();
        while !hw.output().peek().contains(ready) && hw.cycle_count() - start < TEST_TIMEOUT {
            hw.step();
        }
        assert!(hw.output().peek().contains(ready));
        let addr = hw.i3c_address().unwrap();
        let port = hw.i3c_port().unwrap();
        let target = hw.i3c_target();
        let worker = spawn_with_emulator_state(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
                scenario(&mut BufferedStream::new(stream), addr, target);
            }));
            // Failure as well as success must release the main stepping loop.
            stop_emulator();
            result
        });
        let start = hw.cycle_count();
        while hw.exit_status().is_none()
            && hw.output().exit_status().is_none()
            && hw.cycle_count() - start < TEST_TIMEOUT
        {
            hw.step();
        }
        let timed_out = hw.cycle_count() - start >= TEST_TIMEOUT;
        stop_emulator();
        if let Err(panic) = worker.join().unwrap() {
            resume_unwind(panic);
        }
        assert!(!timed_out, "I3C fault test timeout");
        assert_eq!(hw.mci_fw_fatal_error(), None, "I3C firmware fatal error");
        assert!(hw.step_until_exit_success().is_ok());
        lock.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn test_linux_i3c_contract_mctp_control() {
        run_i3c_test(
            "test-mctp-linux-i3c",
            "[mcu-runtime] Entering main loop.",
            |stream, addr, target| {
                let initial_attempts = target.ibi_attempts();
                target.queue_ibi_outcome(I3cIbiOutcome::Complete {
                    status: I3cIbiStatus::Nack,
                    after_polls: 1,
                });
                let eid = 0x0a;
                let versions = [
                    VersionEntry::from_u32(0xF1F0FF00),
                    VersionEntry::from_u32(0xF1F1FF00),
                    VersionEntry::from_u32(0xF1F2FF00),
                    VersionEntry::from_u32(0xF1F3F300),
                ];
                let version_response = get_version_support_resp_bytes(0, Some(&versions));
                let cases = [
                    (
                        0,
                        0,
                        MCTPCtrlCmd::GetEID,
                        vec![],
                        get_eid_resp_bytes(CmdCompletionCode::Success, 0),
                    ),
                    (
                        0,
                        0,
                        MCTPCtrlCmd::SetEID,
                        set_eid_req_bytes(SetEIDOp::SetEID, eid),
                        set_eid_resp_bytes(
                            CmdCompletionCode::Success,
                            SetEIDStatus::Accepted,
                            SetEIDAllocStatus::NoEIDPool,
                            eid,
                        ),
                    ),
                    (
                        eid,
                        eid,
                        MCTPCtrlCmd::GetEID,
                        vec![],
                        get_eid_resp_bytes(CmdCompletionCode::Success, eid),
                    ),
                    (
                        eid,
                        eid,
                        MCTPCtrlCmd::GetEndpointUUID,
                        vec![],
                        get_endpoint_uuid_resp_bytes(CmdCompletionCode::Success, &[0; 16]),
                    ),
                    (
                        eid,
                        eid,
                        MCTPCtrlCmd::GetMctpVersionSupport,
                        vec![0xff],
                        version_response.clone(),
                    ),
                    (
                        eid,
                        eid,
                        MCTPCtrlCmd::GetMctpVersionSupport,
                        vec![0],
                        version_response,
                    ),
                    (
                        eid,
                        eid,
                        MCTPCtrlCmd::GetMsgTypeSupport,
                        vec![],
                        generate_msg_type_support_resp_bytes(
                            0,
                            &[
                                MctpMsgType::Ctrl,
                                MctpMsgType::Pldm,
                                MctpMsgType::Spdm,
                                MctpMsgType::Caliptra,
                            ],
                        ),
                    ),
                ];
                let request_count = cases.len();
                for (instance, (destination, source, command, request, expected)) in
                    cases.into_iter().enumerate()
                {
                    assert_eq!(
                        linux_control_exchange(
                            stream,
                            addr,
                            destination,
                            source,
                            instance as u8,
                            command,
                            &request
                        ),
                        expected
                    );
                }
                for instance in 8..16 {
                    assert_eq!(
                        linux_control_exchange(
                            stream,
                            addr,
                            eid,
                            eid,
                            instance,
                            MCTPCtrlCmd::GetEID,
                            &[]
                        ),
                        get_eid_resp_bytes(CmdCompletionCode::Success, eid)
                    );
                }
                assert_eq!(
                    target.ibi_attempts(),
                    initial_attempts + request_count + 8 + 1
                );
                assert!(!target.has_pending_response());
            },
        );
    }

    #[test]
    fn test_linux_i3c_contract_rejects_legacy_ibi() {
        run_echo_test(|stream, addr, target| {
            assert!(stream.send_private_write(addr, vec![1, 2, 3, 4]));
            assert_eq!(linux_read_packet(stream, addr, 256), None);
            assert_silent(stream, addr);
            assert!(target.has_pending_response());
        });
    }

    #[test]
    fn test_i3c_echo_rx_error_and_oversize_recovery() {
        run_echo_test(|stream, addr, target| {
            let initial_attempts = target.ibi_attempts();
            target.queue_rx_error(1);
            assert!(stream.send_private_write(addr, vec![0xaa; 5]));
            assert_silent(stream, addr);
            // 250 payload bytes + PEC exceeds the driver's 250-byte maximum.
            assert!(stream.send_private_write(addr, vec![0x55; 250]));
            assert_silent(stream, addr);
            assert_eq!(target.ibi_attempts(), initial_attempts);
            for len in [1, 3, 4, 5, 248, 249] {
                echo(stream, addr, (0..len).map(|i| i as u8).collect());
            }
            assert_eq!(target.ibi_attempts(), initial_attempts + 6);
        });
    }

    #[test]
    fn test_i3c_echo_ibi_failure_resend_and_delayed_completion() {
        run_echo_test(|stream, addr, target| {
            let initial_attempts = target.ibi_attempts();
            for status in [
                I3cIbiStatus::Nack,
                I3cIbiStatus::PartialData,
                I3cIbiStatus::Retry,
                I3cIbiStatus::AddressArbitration,
            ] {
                target.queue_ibi_outcome(I3cIbiOutcome::Complete {
                    status,
                    after_polls: 1,
                });
            }
            target.queue_ibi_outcome(I3cIbiOutcome::Complete {
                status: I3cIbiStatus::Success,
                after_polls: 3,
            });
            echo(stream, addr, vec![0xa5; 249]);
            assert_eq!(target.ibi_attempts(), initial_attempts + 5);
            // Both RX and TX ownership must recover for the next transaction.
            echo(stream, addr, vec![1, 2, 3, 4]);
            assert_eq!(target.ibi_attempts(), initial_attempts + 6);
        });
    }

    #[test]
    fn test_i3c_missing_ibi_completion_keeps_tx_pending() {
        run_echo_test(|stream, addr, target| {
            let initial_attempts = target.ibi_attempts();
            target.queue_ibi_outcome(I3cIbiOutcome::Missing);
            assert!(stream.send_private_write(addr, vec![1, 2, 3, 4]));
            assert_silent(stream, addr);
            assert_eq!(target.ibi_attempts(), initial_attempts + 1);
            // No timeout/retry cap is introduced: the shared echo buffer is
            // still owned by TX, so another write cannot produce another IBI.
            assert!(stream.send_private_write(addr, vec![5, 6, 7, 8]));
            assert_silent(stream, addr);
            assert_eq!(target.ibi_attempts(), initial_attempts + 1);
        });
    }
}
