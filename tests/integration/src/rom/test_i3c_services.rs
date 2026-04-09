// Licensed under the Apache-2.0 license

//! Integration tests for the ROM I3C services mailbox handler.
//!
//! These tests verify that the ROM I3C services loop correctly processes
//! commands received over the I3C TTI interface.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
    use random_port::PortPicker;
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::Ordering;

    /// Boot into I3C services, connect, and send a command. Returns the
    /// hw model output after sending.
    fn boot_and_send_i3c_cmd(cmd: Vec<u8>, expected_output: &str) -> String {
        let i3c_port = PortPicker::new().random(true).pick().unwrap();

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature: Some("test-i3c-services"),
            rom_only: true,
            i3c_port: Some(i3c_port),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let port = hw.i3c_port().unwrap();
        let target_addr = hw.i3c_address().unwrap();

        // By the time boot() returns the ROM is already in the I3C services
        // loop (the FPGA runs autonomously; the emulator stepped through it).
        // Connect to the I3C socket and send the command directly.
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr).expect("Failed to connect to I3C socket");
        let mut stream = BufferedStream::new(stream);
        stream.send_private_write(target_addr, cmd);

        // Step until the expected output appears.
        hw.output().set_search_term(expected_output);
        let start = std::time::Instant::now();
        hw.step_until(|m| {
            m.output().search_matched()
                || m.mci_fw_fatal_error().is_some()
                || start.elapsed().as_secs() > 120
        });

        let output_text = hw.output().take(usize::MAX);
        println!("Test output:\n{output_text}");
        assert!(start.elapsed().as_secs() <= 120, "Test timed out");
        assert_eq!(hw.mci_fw_fatal_error(), None, "ROM hit fatal error");

        drop(stream);
        output_text
    }

    /// Test that the ROM enters I3C services mode and responds to PING.
    #[test]
    fn test_i3c_services_ping() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let output = boot_and_send_i3c_cmd(vec![0x00], "[mcu-rom-i3c-svc] PING received");
        assert!(
            output.contains("[mcu-rom-i3c-svc] PING received"),
            "PING was not received by I3C services handler"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }

    /// Test that the ROM responds with INVALID_CMD for unknown commands.
    #[test]
    fn test_i3c_services_unknown_cmd() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let output = boot_and_send_i3c_cmd(vec![0xFF], "[mcu-rom-i3c-svc] Unknown command: 0xff");
        assert!(
            output.contains("[mcu-rom-i3c-svc] Unknown command: 0xff"),
            "Unknown command was not logged"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
