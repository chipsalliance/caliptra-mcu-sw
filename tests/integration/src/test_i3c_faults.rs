// Licensed under the Apache-2.0 license

//! Emulator-only fault tests, running the actual target driver in MCU firmware.
//! These exercise software state/ownership, not electrical I3C behavior.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_emulator_periph::{I3cIbiOutcome, I3cIbiStatus, I3cTarget};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
    use caliptra_mcu_testing_common::{
        emulator_ticks_elapsed, get_emulator_ticks, is_emulator_running, sleep_emulator_ticks,
        spawn_with_emulator_state, stop_emulator,
    };
    use random_port::PortPicker;
    use std::net::{SocketAddr, TcpStream};
    use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
    use std::sync::atomic::Ordering;

    const TEST_TIMEOUT: u64 = 30_000_000;
    const RESPONSE_TIMEOUT: u64 = 5_000_000;

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
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-i3c-echo"),
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            ..Default::default()
        });
        hw.start_i3c_controller();
        let start = hw.cycle_count();
        while !hw.output().peek().contains("I3C echo ready")
            && hw.cycle_count() - start < TEST_TIMEOUT
        {
            hw.step();
        }
        assert!(hw.output().peek().contains("I3C echo ready"));
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
