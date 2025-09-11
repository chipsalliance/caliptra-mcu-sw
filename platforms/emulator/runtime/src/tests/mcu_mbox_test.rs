// Licensed under the Apache-2.0 license

use crate::run_kernel_op;
use core::cell::Cell;
use kernel::debug;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::static_buf;
use kernel::static_init;
use kernel::utilities::cells::TakeCell;
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::StaticRef;
use mcu_mbox_comm::hil::{Mailbox, MailboxClient, MailboxStatus};
use mcu_mbox_driver::McuMailbox;
use mcu_tock_veer::timers::InternalTimers;
use registers_generated::mci;
use romtime::println;

const TEST_BUF_LEN: usize = 64;
static mut MCU_MAILBOX_TESTER: Option<&'static McuMailboxTester> = None;

pub(crate) fn get_mailbox_tester() -> &'static McuMailboxTester {
    unsafe {
        MCU_MAILBOX_TESTER.unwrap_or_else(|| {
            let chip = crate::CHIP.unwrap();
            let mcu_mbox0 = &chip.peripherals.mcu_mbox0;
            let tx_buf = static_buf!([u32; TEST_BUF_LEN]);
            let tx_buf = tx_buf.write([0u32; TEST_BUF_LEN]) as &'static mut [u32];
            let rx_buf = static_buf!([u32; TEST_BUF_LEN]);
            let rx_buf = rx_buf.write([0u32; TEST_BUF_LEN]) as &'static mut [u32];
            let tester: &'static McuMailboxTester = static_init!(
                McuMailboxTester,
                McuMailboxTester::new(mcu_mbox0, tx_buf, rx_buf)
            );
            tester.driver.set_client(tester);
            tester.register();
            tester.driver.enable();
            MCU_MAILBOX_TESTER = Some(tester);
            tester
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum IoState {
    Idle,
    Received,
    Sent,
    FinishResp,
    Error,
}

pub(crate) struct McuMailboxTester {
    driver: &'static McuMailbox<'static, InternalTimers<'static>>,
    tx_buf: TakeCell<'static, [u32]>, // For sending response
    rx_buf: TakeCell<'static, [u32]>, // For receiving data
    state: Cell<IoState>,
    data_len: Cell<usize>,
    cmd: Cell<u32>,
    deferred_call: DeferredCall,
    response_fn: Cell<Option<fn(&[u32], &mut [u32]) -> usize>>,
}

impl McuMailboxTester {
    pub fn new(
        driver: &'static McuMailbox<'static, InternalTimers<'static>>,
        sent: &'static mut [u32],
        recv: &'static mut [u32],
    ) -> Self {
        Self {
            driver: driver,
            tx_buf: TakeCell::new(sent),
            rx_buf: TakeCell::new(recv),
            state: Cell::new(IoState::Idle),
            data_len: Cell::new(0),
            cmd: Cell::new(0),
            deferred_call: DeferredCall::new(),
            response_fn: Cell::new(None),
        }
    }

    /// Register a function pointer to generate the response pattern.
    pub fn set_response_fn(&self, f: fn(&[u32], &mut [u32]) -> usize) {
        self.response_fn.set(Some(f));
    }

    pub fn reset(&self) {
        self.state.set(IoState::Idle);
        self.data_len.set(0);
        self.cmd.set(0);
        self.deferred_call.set();
        self.response_fn.set(None);
    }

    pub fn get_io_state(&self) -> IoState {
        self.state.get()
    }
}

impl MailboxClient for McuMailboxTester {
    fn request_received(&self, command: u32, rx_buf: &'static mut [u32], dlen: usize) {
        let recv = self.rx_buf.take().expect("rx_buf missing");
        let dw_len = dlen.div_ceil(4);
        if dw_len > recv.len() {
            self.state.set(IoState::Error);
            return;
        }
        // Copy received data directly into tester's rx_buf
        for i in 0..dw_len {
            recv[i] = rx_buf[i];
        }
        // store data len
        self.data_len.set(dw_len);
        // store command
        self.cmd.set(command);
        // Restore driver buffers
        self.driver.restore_rx_buffer(rx_buf);
        // Restore buffers for next test
        self.rx_buf.replace(recv);
        self.state.set(IoState::Received);
        self.deferred_call.set();
    }

    fn send_done(&self, result: Result<(), kernel::ErrorCode>) {
        assert!(result.is_ok(), "Send failed");
        self.state.set(IoState::Sent);
        // Schedule deferred call to handle finish response.
        self.deferred_call.set();
    }

    fn response_received(
        &self,
        _status: MailboxStatus,
        _rx_buf: &'static mut [u32],
        _dw_len: usize,
    ) {
        unimplemented!("Only test MCU mailbox driver as receiver mode");
    }
}

impl DeferredCallClient for McuMailboxTester {
    fn handle_deferred_call(&self) {
        if self.state.get() == IoState::Received && self.data_len.get() > 0 {
            let rx_buf = self.rx_buf.take().expect("rx_buf is missing");
            let tx_buf = self.tx_buf.take().expect("tx_buf is missing");
            let dw_len = self.data_len.get();

            let tx_buf_len = if let Some(f) = self.response_fn.get() {
                // Use the registered function to generate the response
                f(&rx_buf[..dw_len], &mut tx_buf[..])
            } else {
                // Default: loop back
                tx_buf[..dw_len].copy_from_slice(&rx_buf[..dw_len]);
                dw_len
            };

            let _ = self
                .driver
                .send_response(tx_buf.iter().copied(), tx_buf_len * 4);

            self.tx_buf.replace(tx_buf);
            self.rx_buf.replace(rx_buf);
        } else if self.state.get() == IoState::Sent {
            let _ = self.driver.set_mbox_cmd_status(MailboxStatus::Complete);
            self.state.set(IoState::FinishResp);
        }
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}

// Represent an emulated MCI mailbox sender to support testing.
pub struct EmulatedMbxSender<'a> {
    regs: &'a registers_generated::mci::regs::Mci,
}

impl<'a> EmulatedMbxSender<'a> {
    pub fn new(regs: &'a registers_generated::mci::regs::Mci) -> Self {
        Self { regs }
    }

    pub fn send_request(&self, cmd: u32, req_payload: &[u32]) {
        let lock = self.regs.mcu_mbox0_csr_mbox_lock.get();
        assert!(lock == 0, "lock not acquired");
        self.regs.mcu_mbox0_csr_mbox_cmd.set(cmd);
        for (i, &word) in req_payload.iter().enumerate() {
            self.regs.mcu_mbox0_csr_mbox_sram[i].set(word);
        }
        let req_len_in_bytes = req_payload.len() * 4; // Convert dwords to bytes
        self.regs
            .mcu_mbox0_csr_mbox_dlen
            .set(req_len_in_bytes as u32);
        self.regs.mcu_mbox0_csr_mbox_execute.set(1);
    }

    pub fn poll_and_check_response(
        &self,
        tester: &McuMailboxTester,
        resp_buf: &mut [u32],
        expected_resp: &[u32],
        expected_cmd: u32,
        expected_cmd_status: u32,
        timeout: usize,
    ) {
        let mut waited = 0;
        let mut resp_finished = false;
        while waited < timeout {
            // Advance kernel ops to invoke interrupt handling and deferred callback.
            run_kernel_op(1);
            if tester.get_io_state() == IoState::FinishResp {
                resp_finished = true;
                break;
            }
            waited += 1;
        }
        assert!(
            resp_finished,
            "Receiver did not finish response after {} kernel loops",
            timeout
        );

        // Check if we received the expected command
        let cmd = tester.cmd.get();
        assert_eq!(
            cmd, expected_cmd,
            "Unexpected command: {:#x}, expected {:#x}",
            cmd, expected_cmd
        );
        assert!(
            resp_buf.len() >= expected_resp.len(),
            "resp buf is too small"
        );

        // Check mbox_dlen register to ensure it matches expected response length.
        let resp_dw_len = self.regs.mcu_mbox0_csr_mbox_dlen.get() as usize / 4;
        assert_eq!(
            resp_dw_len,
            expected_resp.len(),
            "Response length mismatch: got {}, expected {}",
            resp_dw_len,
            expected_resp.len()
        );
        // Copy the response data from mailbox sram into resp buf.
        for i in 0..expected_resp.len() {
            resp_buf[i] = self.regs.mcu_mbox0_csr_mbox_sram[i].get();
        }
        for i in 0..expected_resp.len() {
            assert_eq!(
                resp_buf[i], expected_resp[i],
                "MCU response mismatch at word {}: got {:#x}, expected {:#x}",
                i, resp_buf[i], expected_resp[i]
            );
        }

        // Check status register
        let status = self.regs.mcu_mbox0_csr_mbox_cmd_status.get();
        assert!(
            status == expected_cmd_status,
            "Unexpected status: {:#x}, expected complete {:#x}",
            status,
            expected_cmd_status
        );
    }

    pub fn finish(&self) {
        self.regs.mcu_mbox0_csr_mbox_execute.set(0);
    }
}

pub fn test_mcu_mbox() -> Option<u32> {
    test_mcu_mbox_loopback();
    test_mcu_mbox_custom_response();
    romtime::println!("MCU mailbox tests pass");
    Some(0)
}

fn test_mcu_mbox_loopback() {
    romtime::println!("Starting MCU mailbox test loopback");
    fn expected_resp(input: &[u32], output: &mut [u32]) -> usize {
        let n = input.len();
        output[..n].copy_from_slice(&input[..n]);
        n
    }
    run_mcu_mailbox_test(
        0x55,
        req_pattern,
        None,
        expected_resp,
        mci::bits::MboxCmdStatus::Status::CmdComplete.value,
    );
}

fn test_mcu_mbox_custom_response() {
    romtime::println!("Starting MCU mailbox test custom response");
    run_mcu_mailbox_test(
        0x77,
        req_pattern,
        Some(reverse_half),
        reverse_half,
        mci::bits::MboxCmdStatus::Status::CmdComplete.value,
    );
}

fn run_mcu_mailbox_test(
    cmd: u32,
    req_pattern: fn(&mut [u32]),
    resp_fn: Option<fn(&[u32], &mut [u32]) -> usize>,
    expected_resp: fn(&[u32], &mut [u32]) -> usize,
    expected_cmd_status: u32,
) {
    let mcu_mailbox_tester = get_mailbox_tester();
    // Reset tester before starting a new test.
    mcu_mailbox_tester.reset();

    if let Some(f) = resp_fn {
        mcu_mailbox_tester.set_response_fn(f);
    }
    let regs: StaticRef<mci::regs::Mci> =
        unsafe { StaticRef::new(mci::MCI_TOP_ADDR as *const mci::regs::Mci) };
    let soc_sender = EmulatedMbxSender::new(&*regs);

    let mut req_payload = [0u32; TEST_BUF_LEN];
    req_pattern(&mut req_payload);
    soc_sender.send_request(cmd, &req_payload);

    let mut soc_recv_resp = [0x0u32; TEST_BUF_LEN];
    let mut expected = [0u32; TEST_BUF_LEN];
    let n = expected_resp(&req_payload, &mut expected);
    soc_sender.poll_and_check_response(
        mcu_mailbox_tester,
        &mut soc_recv_resp,
        &expected[..n],
        cmd,
        expected_cmd_status,
        50000,
    );
    soc_sender.finish();
}

fn reverse_half(input: &[u32], output: &mut [u32]) -> usize {
    let n = input.len() / 2;
    for i in 0..n {
        output[i] = input[n - 1 - i];
    }
    n
}

fn req_pattern(buf: &mut [u32]) {
    for i in 0..buf.len() {
        buf[i] = i as u32;
    }
}
