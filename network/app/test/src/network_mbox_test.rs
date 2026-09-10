/*++

Licensed under the Apache-2.0 license.

File Name:

    network_mbox_test.rs

Abstract:

    Network Mailbox communication test for the Network Coprocessor.

    This test app listens for a mailbox request from the MCU, reads the
    command and data, echoes back the data with each dword incremented
    by 1, and sets the target status to CmdComplete with Done.

    Uses the NetworkMboxDriver and NetworkMailboxClient trait for
    receiving requests and sending responses.

--*/

use caliptra_mcu_network_drivers::network_mbox::NetworkMboxDriver;
use caliptra_mcu_network_drivers::println;
use caliptra_mcu_network_hil::network_mbox::{
    NetworkMailbox, NetworkMailboxClient, NetworkMboxStatus, NetworkMboxTargetStatus, Result,
};

use core::cell::Cell;

/// Test command: echo back data with each dword incremented by 1.
pub const TEST_CMD_ECHO_INCREMENT: u32 = 0x0001;

/// Simple client that handles the echo-increment test.
struct EchoIncrementClient<'a> {
    driver: &'a NetworkMboxDriver<'a>,
    done: Cell<bool>,
    passed: Cell<bool>,
}

impl<'a> EchoIncrementClient<'a> {
    fn new(driver: &'a NetworkMboxDriver<'a>) -> Self {
        Self {
            driver,
            done: Cell::new(false),
            passed: Cell::new(false),
        }
    }
}

impl<'a> NetworkMailboxClient for EchoIncrementClient<'a> {
    fn request_received(
        &self,
        command: u32,
        _user: u32,
        rx_buf: &'static mut [u32],
        dlen: usize,
    ) -> Result<()> {
        let dw_len = dlen.div_ceil(4);

        println!("[net-mbox] Received cmd={:#x}, dlen={}", command, dlen);

        if command == TEST_CMD_ECHO_INCREMENT {
            // Increment each dword in-place.
            for i in 0..dw_len {
                rx_buf[i] = rx_buf[i].wrapping_add(1);
            }

            // Send response using the driver (writes back modified data + dlen).
            let _ = self
                .driver
                .send_response(rx_buf[..dw_len].iter().copied(), dlen);

            // Set target status to CmdComplete with Done.
            let _ = self
                .driver
                .set_target_status(NetworkMboxStatus::CmdComplete);

            println!("[net-mbox] Response sent, test PASSED!");
            self.passed.set(true);
        } else {
            println!("[net-mbox] Unknown command: {:#x}", command);
            let _ = self.driver.set_target_status(NetworkMboxStatus::CmdFailure);
        }

        self.driver.restore_rx_buffer(rx_buf);
        self.done.set(true);
        Ok(())
    }

    fn response_received(
        &self,
        _status: NetworkMboxTargetStatus,
        _rx_buf: &'static mut [u32],
        _dlen: usize,
    ) {
        // Not used in receiver mode.
    }

    fn send_done(&self, _result: caliptra_mcu_network_hil::network_mbox::Result<()>) {
        // Not used in receiver mode.
    }
}

pub fn run() {
    println!();
    println!("=====================================");
    println!("  Network Mbox Test Started!         ");
    println!("=====================================");
    println!();

    let driver = NetworkMboxDriver::new();
    let client = EchoIncrementClient::new(&driver);
    driver.set_client(&client);
    driver.enable(); // Set to RxWait state.

    println!("[net-mbox] Waiting for request (execute bit)...");

    // Poll until the client has handled the request.
    let max_polls: u64 = 500_000_000;
    for _ in 0..max_polls {
        driver.poll();
        if client.done.get() {
            break;
        }
    }

    if !client.done.get() {
        println!("[net-mbox] ERROR: Timed out waiting for request");
    }

    loop {
        core::hint::spin_loop();
    }
}
