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
    tx_rx_buf: TakeCell<'static, [u32]>,
    state: Cell<IoState>,
    data_len: Cell<usize>,
    deferred_call: DeferredCall,
}

impl EmulatedDoeTransportTester<'_> {
    pub fn new(
        doe_mbox: &'static EmulatedDoeTransport<'static, InternalTimers<'static>>,
        test_buf: &'static mut [u32],
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

            _ = self.doe_mbox.transmit(test_tx_buf.iter().copied(), len);
            self.tx_rx_buf.replace(test_tx_buf);
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

        if len_dw > TEST_BUF_LEN {
            panic!("Received data length exceeds buffer size");
        }

        // Clear the buffer before receiving new data
        let test_rx_buf = self
            .tx_rx_buf
            .take()
            .expect("rx_buf not available for receiving data");

        for (i, &val) in rx_buf.iter().enumerate().take(len_dw) {
            test_rx_buf[i] = val;
        }

        // Set the received buffer back in the doe_mbox
        self.doe_mbox.set_rx_buffer(rx_buf);

        self.tx_rx_buf.replace(test_rx_buf);
        self.data_len.set(len_dw); // Store the length of the received data
        self.deferred_call.set();

        self.state.set(IoState::Received);
    }
}

impl<'a> DoeTransportTxClient<'a> for EmulatedDoeTransportTester<'a> {
    fn send_done(&self, result: Result<(), kernel::ErrorCode>) {
        assert!(result.is_ok(), "Failed to send data: {:?}", result);

        self.state.set(IoState::Idle);
    }
}

pub fn test_doe_transport_loopback() -> Option<u32> {
    let peripherals = unsafe { EMULATOR_PERIPHERALS.unwrap() };
    let doe_mbox = &peripherals.doe_transport;

    let tx_rx_buffer = unsafe { static_buf!([u32; TEST_BUF_LEN]) };
    let tx_rx_buffer = tx_rx_buffer.write([0u32; TEST_BUF_LEN]) as &'static mut [u32];
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
