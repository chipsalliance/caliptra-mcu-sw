/*++

Licensed under the Apache-2.0 license.

File Name:

    network_mbox_test.rs

Abstract:

    MCU ROM test for network mailbox communication.

--*/

use caliptra_mcu_network_drivers::network_mbox::NetworkMboxDriver;
use caliptra_mcu_network_hil::network_mbox::{
    NetworkMailbox, NetworkMailboxClient, NetworkMboxError, NetworkMboxStatus,
    NetworkMboxTargetStatus, Result,
};
use core::cell::Cell;

const TEST_CMD_ECHO_INCREMENT: u32 = 0x0001;
const TEST_DATA: [u32; 4] = [0x1000, 0x2000, 0x3000, 0x4000];

/// Client that verifies echo-increment response from the Network CoP.
struct VerifyResponseClient {
    done: Cell<bool>,
    passed: Cell<bool>,
}

impl VerifyResponseClient {
    fn new() -> Self {
        Self {
            done: Cell::new(false),
            passed: Cell::new(false),
        }
    }
}

impl NetworkMailboxClient for VerifyResponseClient {
    fn request_received(
        &self,
        _command: u32,
        _user: u32,
        _rx_buf: &'static mut [u32],
        _dlen: usize,
    ) -> Result<()> {
        // Not used in sender mode.
        Ok(())
    }

    fn response_received(
        &self,
        status: NetworkMboxTargetStatus,
        rx_buf: &'static mut [u32],
        dlen: usize,
    ) {
        let dw_len = dlen.div_ceil(4);

        if status.status != NetworkMboxStatus::CmdComplete {
            caliptra_mcu_romtime::println!(
                "[mcu-rom] Network mbox test FAILED: unexpected status {:?}",
                status.status
            );
            self.done.set(true);
            return;
        }

        let mut pass = true;
        for (i, &original) in TEST_DATA.iter().enumerate() {
            if i >= dw_len {
                break;
            }
            let expected = original.wrapping_add(1);
            let actual = rx_buf[i];
            if actual != expected {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom] Network mbox test FAILED: SRAM[{}] = {:#x}, expected {:#x}",
                    i,
                    actual,
                    expected
                );
                pass = false;
            }
        }

        if pass {
            caliptra_mcu_romtime::println!("[mcu-rom] Network mbox test PASSED!");
        }
        self.passed.set(pass);
        self.done.set(true);
    }

    fn send_done(&self, _result: caliptra_mcu_network_hil::network_mbox::Result<()>) {
        // Not used in this test.
    }
}

pub fn run() {
    let dlen = TEST_DATA.len() * 4;

    let driver = NetworkMboxDriver::new();
    let client = VerifyResponseClient::new();
    driver.set_client(&client);

    caliptra_mcu_romtime::println!("[mcu-rom] Network mbox test: sending request via driver...");

    // Retry send_request until the lock is acquired.
    loop {
        match driver.send_request(
            TEST_CMD_ECHO_INCREMENT,
            0, // target_user
            TEST_DATA.iter().copied(),
            dlen,
        ) {
            Ok(()) => break,
            Err(NetworkMboxError::Locked) => {
                // Lock is held, retry.
                continue;
            }
            Err(e) => {
                caliptra_mcu_romtime::println!(
                    "[mcu-rom] Network mbox test FAILED: send_request error {:?}",
                    e
                );
                return;
            }
        }
    }

    caliptra_mcu_romtime::println!(
        "[mcu-rom] Network mbox test: request sent, waiting for response..."
    );

    // Poll until the client callback fires.
    loop {
        driver.poll();
        if client.done.get() {
            break;
        }
    }
}
