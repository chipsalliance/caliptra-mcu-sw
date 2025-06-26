// Licensed under the Apache-2.0 license

// Test DOE MBOX driver: send data and ensure it is written back.

use crate::EMULATOR_PERIPHERALS;
use core::cell::Cell;
use core::cell::RefCell;
use core::fmt::Write;
use doe_mbox_driver::EmulatedDoeTransport;
use doe_transport::hil::{DoeTransport, DoeTransportRxClient, DoeTransportTxClient};
use kernel::debug;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::utilities::cells::TakeCell;
use kernel::{static_buf, static_init};
use mcu_tock_veer::timers::InternalTimers;
use romtime::println;

pub const TEST_BUF_LEN: usize = 128 * 4; // 128 dwords, 512 bytes

#[derive(Clone, Copy, PartialEq)]
pub enum IoState {
    Idle,
    Received,
    Sent,
}

struct EmulatedDoeTransportTester<'a> {
    doe_mbox: &'a EmulatedDoeTransport<'static, InternalTimers<'static>>,
    tx_rx_buf: TakeCell<'static, [u8]>,
    state: Cell<IoState>,
    data_len: Cell<usize>,
    deferred_call: DeferredCall,
}

impl EmulatedDoeTransportTester<'_> {
    pub fn new(
        doe_mbox: &'static EmulatedDoeTransport<'static, InternalTimers<'static>>,
        test_buf: &'static mut [u8],
    ) -> Self {
        Self {
            doe_mbox,
            tx_rx_buf: TakeCell::new(test_buf),
            data_len: Cell::new(0),
            deferred_call: DeferredCall::new(),
            state: Cell::new(IoState::Idle),
        }
    }
}

impl<'a> DeferredCallClient for EmulatedDoeTransportTester<'a> {
    fn handle_deferred_call(&self) {
        if self.state.get() == IoState::Received && self.data_len.get() > 0 {
            let test_tx_buf = self.tx_rx_buf.take().expect("tx_buf not initialized");
            let len = self.data_len.get();

            println!("EMULATED_DOE_TRANSPORT_TESTER: Sending {} bytes", len);

            _ = self.doe_mbox.transmit(test_tx_buf, len);
            self.state.set(IoState::Sent);
        }
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}

impl DoeTransportRxClient for EmulatedDoeTransportTester<'_> {
    fn receive(&self, rx_buf: &'static mut [u32], len_dw: usize) {
        println!("EMULATED_DOE_TRANSPORT_TESTER: Received {} dwords", len_dw);

        if len_dw * 4 > TEST_BUF_LEN {
            panic!("Received data length exceeds buffer size");
        }

        // Clear the buffer before receiving new data
        let test_rx_buf = self
            .tx_rx_buf
            .take()
            .expect("rx_buf not available for receiving data");

        for (i, &val) in rx_buf.iter().enumerate().take(len_dw) {
            let bytes = val.to_le_bytes();
            let start = i * 4;
            let end = start + 4;
            test_rx_buf[start..end].copy_from_slice(&bytes);
        }

        // Set the received buffer back in the doe_mbox
        self.doe_mbox.set_rx_buffer(rx_buf);

        self.tx_rx_buf.replace(test_rx_buf);
        self.data_len.set(len_dw * 4); // Store the length of the received data
        self.deferred_call.set();

        self.state.set(IoState::Received);
    }

    // fn receive_expected(&self) {
    //     // This function can be used to handle expected data reception
    //     // For now, we just set the state to Received
    //     self.doe_mbox
    //         .set_rx_buffer(self.tx_rx_buf.take().expect("rx_buf not available"));
    // }
}

impl<'a> DoeTransportTxClient<'a> for EmulatedDoeTransportTester<'a> {
    fn send_done(&self, buf: &'a [u8], result: Result<(), kernel::ErrorCode>) {
        assert!(result.is_ok(), "Failed to send data: {:?}", result);

        let buf_ptr = buf.as_ptr() as *mut u8;
        let buf_len = buf.len();
        // SAFETY: The buffer returned here is the same one previously passed to transmit().
        // We can safely reconstruct a static mutable slice for reuse in next receive operation in test.
        let static_buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buf_len) };
        self.tx_rx_buf.replace(static_buf);
        self.state.set(IoState::Idle);
    }
}

pub fn test_doe_transport_loopback() -> Option<u32> {
    let peripherals = unsafe { EMULATOR_PERIPHERALS.unwrap() };
    let doe_mbox = &peripherals.doe_transport;

    let tx_rx_buffer = unsafe { static_buf!([u8; TEST_BUF_LEN]) };
    let tx_rx_buffer = tx_rx_buffer.write([0u8; TEST_BUF_LEN]) as &'static mut [u8];
    let tester = unsafe {
        static_init!(
            EmulatedDoeTransportTester<'static>,
            EmulatedDoeTransportTester::new(doe_mbox, tx_rx_buffer)
        )
    };

    doe_mbox.set_rx_client(tester);
    doe_mbox.set_tx_client(tester);
    tester.register();
    tester.deferred_call.set();
    doe_mbox.enable().unwrap();
    None
}
