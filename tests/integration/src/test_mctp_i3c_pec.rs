// Licensed under the Apache-2.0 license

//! Emulator test for the MCTP I3C binding PEC when the controller assigns the
//! target a new dynamic address after the runtime has set up MCTP.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
    use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
    use caliptra_mcu_testing_common::mctp_util::base_protocol::{
        MCTPHdr, MctpMsgType, LOCAL_TEST_ENDPOINT_EID, MCTP_HDR_SIZE,
    };
    use caliptra_mcu_testing_common::mctp_util::ctrl_protocol::{
        get_eid_resp_bytes, CmdCompletionCode, MCTPCtrlCmd, MCTPCtrlMsgHdr,
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
    const REASSIGNED_ADDR: u8 = 0x2a;

    fn wait_for<T>(what: &str, mut read: impl FnMut() -> Option<T>) -> T {
        let start = get_emulator_ticks();
        loop {
            if let Some(value) = read() {
                return value;
            }
            assert!(is_emulator_running(), "firmware stopped before {what}");
            assert!(
                !emulator_ticks_elapsed(start, RESPONSE_TIMEOUT),
                "timed out waiting for {what}"
            );
            sleep_emulator_ticks(10_000);
        }
    }

    /// Sends Get Endpoint ID to `addr` the way a host does: the request PEC is
    /// computed with `addr`, and the response PEC is checked against `addr`.
    fn get_eid(stream: &mut BufferedStream, addr: u8, instance_id: u8) {
        let tag = instance_id & 7;
        let mut header = MCTPHdr::new();
        header.prepare_header(0, LOCAL_TEST_ENDPOINT_EID, 1, 1, 0, 1, tag);
        let mut control = MCTPCtrlMsgHdr::new();
        control.set_rq(1);
        control.set_instance_id(instance_id);
        control.set_cmd(MCTPCtrlCmd::GetEID as u8);
        let mut request = header.as_bytes().to_vec();
        request.push(MctpMsgType::Ctrl as u8);
        request.extend_from_slice(control.as_bytes());
        assert!(stream.send_private_write(addr, request));

        // A request whose PEC does not match the target's address is dropped,
        // so the target never announces a response.
        wait_for(&format!("pending-read IBI from {addr:#04x}"), || {
            stream.receive_ibi_packet(addr)
        });
        stream.send_private_read_request(addr);
        let packet = wait_for(&format!("private read from {addr:#04x}"), || {
            stream.receive_private_read_raw(addr)
        });
        let (&received_pec, response) = packet.split_last().unwrap();
        let pec = response.iter().fold(
            caliptra_mcu_romtime::crc8(0, (addr << 1) | 1),
            |crc, byte| caliptra_mcu_romtime::crc8(crc, *byte),
        );
        assert_eq!(received_pec, pec, "response PEC does not use {addr:#04x}");

        let response_header =
            MCTPHdr::<[u8; MCTP_HDR_SIZE]>::read_from_bytes(&response[..MCTP_HDR_SIZE]).unwrap();
        header.prepare_header(LOCAL_TEST_ENDPOINT_EID, 0, 1, 1, 0, 0, tag);
        assert_eq!(response_header, header);
        assert_eq!(response[MCTP_HDR_SIZE], MctpMsgType::Ctrl as u8);
        control.set_rq(0);
        assert_eq!(
            &response[MCTP_HDR_SIZE + 1..MCTP_HDR_SIZE + 3],
            control.as_bytes()
        );
        assert_eq!(
            &response[MCTP_HDR_SIZE + 3..],
            get_eid_resp_bytes(CmdCompletionCode::Success, 0).as_slice()
        );
    }

    #[test]
    fn test_mctp_i3c_pec_after_dynamic_address_change() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-mctp-ctrl-cmds"),
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            ..Default::default()
        });
        hw.start_i3c_controller();
        let start = hw.cycle_count();
        while !hw
            .output()
            .peek()
            .contains("[mcu-runtime] Entering main loop.")
            && hw.cycle_count() - start < TEST_TIMEOUT
        {
            hw.step();
        }
        assert!(hw
            .output()
            .peek()
            .contains("[mcu-runtime] Entering main loop."));
        let addr = hw.i3c_address().unwrap();
        assert_ne!(addr, REASSIGNED_ADDR);
        let port = hw.i3c_port().unwrap();
        let mut target = hw.i3c_target();
        let worker = spawn_with_emulator_state(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
                let mut stream = BufferedStream::new(stream);
                get_eid(&mut stream, addr, 0);

                // The controller re-runs DAA (RSTDAA + ENTDAA) after MCTP is set
                // up and assigns a different dynamic address.
                target.set_address(DynamicI3cAddress::new(REASSIGNED_ADDR).unwrap());
                get_eid(&mut stream, REASSIGNED_ADDR, 1);
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
        assert!(!timed_out, "MCTP I3C PEC test timeout");
        assert_eq!(hw.mci_fw_fatal_error(), None, "firmware fatal error");
        assert!(hw.step_until_exit_success().is_ok());
        lock.fetch_add(1, Ordering::Relaxed);
    }
}
