//! Licensed under the Apache-2.0 license

//! This module tests the I3C constant writes functionality

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::McuHwModel;
    use mcu_testing_common::i3c_socket::BufferedStream;
    use mcu_testing_common::{sleep_emulator_ticks, wait_for_runtime_start, MCU_RUNNING};
    use random_port::PortPicker;
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::Ordering;
    use std::thread;

    #[test]
    fn test_i3c_constant_writes() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-i3c-constant-writes"),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let port = hw.i3c_port().unwrap();
        let target_addr = hw.i3c_address().unwrap();

        // Spawn a thread to send constant writes to the I3C target
        thread::spawn(move || {
            wait_for_runtime_start();

            if !MCU_RUNNING.load(Ordering::Relaxed) {
                return;
            }

            // Give some time for the firmware to set up the I3C RX client
            sleep_emulator_ticks(100_000);

            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            if let Ok(stream) = TcpStream::connect(addr) {
                let mut stream = BufferedStream::new(stream);

                // Send 15+ writes to trigger the test pass condition (needs 10)
                // Send quickly to beat the firmware timeout
                for i in 0..15 {
                    if !MCU_RUNNING.load(Ordering::Relaxed) {
                        break;
                    }
                    let data = vec![0x01, 0x02, 0x03, (i & 0xff) as u8];
                    stream.send_private_write(target_addr, data);
                    sleep_emulator_ticks(10_000);
                }
            }
        });

        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, Ordering::Relaxed);
    }
}
