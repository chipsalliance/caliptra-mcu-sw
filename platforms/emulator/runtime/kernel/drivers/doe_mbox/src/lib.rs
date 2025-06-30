// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use doe_transport::hil::{DoeTransport, DoeTransportRxClient, DoeTransportTxClient};

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use core::cell::Cell;
use kernel::hil::time::{Alarm, AlarmClient, Time};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::{debug, ErrorCode};
use registers_generated::doe_mbox::bits::{DoeMboxEvent, DoeMboxStatus};
use registers_generated::doe_mbox::regs::DoeMbox;
use registers_generated::doe_mbox::DOE_MBOX_ADDR;

pub const DOE_MBOX_BASE: StaticRef<DoeMbox> =
    unsafe { StaticRef::new(DOE_MBOX_ADDR as *const DoeMbox) };

const DOE_MBOX_SRAM_ADDR: u32 = DOE_MBOX_ADDR + 0x1000; // SRAM offset from DOE Mbox base address

#[derive(Copy, Clone, Debug, PartialEq)]
enum DoeMboxState {
    Idle,
    RxWait,       // Driver waiting for data to be received from SoC.
    TxInProgress, // Transmit is in progress. Need to wait for send_done.
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum TimerMode {
    NoTimer,
    ReceiveRetry,
    SendDoneDefer,
}

pub struct EmulatedDoeTransport<'a, A: Alarm<'a>> {
    registers: StaticRef<DoeMbox>,
    tx_client: OptionalCell<&'a dyn DoeTransportTxClient<'a>>,
    rx_client: OptionalCell<&'a dyn DoeTransportRxClient>,

    // Buffer to send/receive the DOE data object
    doe_data_buf: TakeCell<'static, [u32]>,
    doe_data_buf_len: usize,

    pending_reset: Cell<bool>,

    state: Cell<DoeMboxState>,
    timer_mode: Cell<TimerMode>,
    alarm: VirtualMuxAlarm<'a, A>,
}

fn doe_mbox_sram_static_ref(len: usize) -> &'static mut [u32] {
    // SAFETY: We assume the SRAM is initialized and the address is valid.
    // The length is provided by the caller and should match the actual SRAM size.
    unsafe { core::slice::from_raw_parts_mut(DOE_MBOX_SRAM_ADDR as *mut u32, len) }
}

impl<'a, A: Alarm<'a>> EmulatedDoeTransport<'a, A> {
    // This is just to add a delay calling `send_done` to emulate the hardware behavior.
    // Number of ticks to defer send_done
    const DEFER_SEND_DONE_TICKS: u32 = 1000;

    const RECEIVE_RETRY_TICKS: u32 = 1000;

    pub fn new(
        base: StaticRef<DoeMbox>,
        alarm: &'a MuxAlarm<'a, A>,
    ) -> EmulatedDoeTransport<'a, A> {
        let len = base.doe_mbox_sram.len();

        EmulatedDoeTransport {
            registers: base,
            tx_client: OptionalCell::empty(),
            rx_client: OptionalCell::empty(),
            doe_data_buf: TakeCell::new(doe_mbox_sram_static_ref(len)),
            doe_data_buf_len: len,
            pending_reset: Cell::new(false),
            state: Cell::new(DoeMboxState::Idle),
            timer_mode: Cell::new(TimerMode::NoTimer),
            alarm: VirtualMuxAlarm::new(alarm),
        }
    }

    pub fn init(&'static self) {
        self.alarm.setup();
        self.alarm.set_alarm_client(self);
        // Start receiving data
        self.state.set(DoeMboxState::RxWait);
    }

    fn schedule_send_done(&self) {
        self.timer_mode.set(TimerMode::SendDoneDefer);
        let now = self.alarm.now();
        self.alarm
            .set_alarm(now, (Self::DEFER_SEND_DONE_TICKS).into());
    }

    fn schedule_receive_retry(&self) {
        self.timer_mode.set(TimerMode::ReceiveRetry);
        let now = self.alarm.now();
        self.alarm
            .set_alarm(now, (Self::RECEIVE_RETRY_TICKS).into());
    }

    fn reset_state(&self) {
        // Reset the doe_box_status register
        self.timer_mode.set(TimerMode::NoTimer);
        self.state.set(DoeMboxState::RxWait);
        self.pending_reset.set(false);
        self.registers
            .doe_mbox_status
            .write(DoeMboxStatus::ResetAck::SET);
    }

    pub fn handle_interrupt(&self) {
        let event = self.registers.doe_mbox_event.extract();

        // Clear the status register
        self.registers.doe_mbox_status.set(0);

        // 1. Handle RESET_REQ regardless of current state
        if event.is_set(DoeMboxEvent::ResetReq) {
            self.handle_reset_request();
        }

        // 2. Only handle DATA_READY if in RxWait state
        if event.is_set(DoeMboxEvent::DataReady) {
            self.handle_receive_data();
        }
    }

    fn handle_reset_request(&self) {
        // Write 1 to clear the RESET_REQ event
        self.registers
            .doe_mbox_event
            .modify(DoeMboxEvent::ResetReq::SET);
        // If we are in TxInProgress state, we need to defer the reset
        if self.state.get() == DoeMboxState::TxInProgress {
            self.pending_reset.set(true);
            return;
        }

        // Reset the DOE Mbox status and state
        self.reset_state();
    }

    fn handle_receive_data(&self) {
        if self.state.get() != DoeMboxState::RxWait {
            // Not currently waiting for data, ignore DATA_READY
            return;
        }
        let data_len = self.registers.doe_mbox_dlen.get() as usize;
        // If the data length is not valid, set error bit
        if data_len > self.max_data_object_size() {
            self.registers
                .doe_mbox_status
                .write(DoeMboxStatus::Error::SET);
            return;
        }

        if self.doe_data_buf.is_none() {
            // The client has not restored the DOE data buffer,
            // so we cannot receive data. Try receiving again later.
            debug!("DOE_MBOX_DRIVER: No DOE data buffer available. Cannot receive data.");
            self.schedule_receive_retry();
            return;
        }

        // Clear the DATA_READY event, writing 1 to the event register
        self.registers
            .doe_mbox_event
            .modify(DoeMboxEvent::DataReady::SET);

        let doe_buf = match self.doe_data_buf.take() {
            Some(buf) => buf,
            None => {
                debug!("DOE_MBOX_DRIVER: Error! No DOE data buffer available. This should not happen in normal operation.");
                self.registers
                    .doe_mbox_status
                    .write(DoeMboxStatus::Error::SET);
                return;
            }
        };

        // Send the data to the client
        match self.rx_client.get() {
            Some(client) => {
                // It is expected that the client restores buffer in receive() with set_rx_buffer().
                client.receive(doe_buf, data_len);
            }
            None => {
                debug!("DOE_MBOX_DRIVER: No RX client available to receive data");
            }
        }
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for EmulatedDoeTransport<'a, A> {
    fn alarm(&self) {
        match self.timer_mode.get() {
            TimerMode::NoTimer => {
                // Spurious alarm, nothing to do.
            }
            TimerMode::ReceiveRetry => {
                self.handle_receive_data();
            }
            TimerMode::SendDoneDefer => {
                self.tx_client.map(|client| {
                    client.send_done(Ok(()));
                });
                self.registers
                    .doe_mbox_status
                    .write(DoeMboxStatus::DataReady::SET);
                if self.pending_reset.get() {
                    // reset the state if we had a pending reset
                    self.reset_state();
                } else {
                    // After send_done, go back to RxWait
                    self.state.set(DoeMboxState::RxWait);
                }
            }
        }
        // Clear timer mode after handling
        self.timer_mode.set(TimerMode::NoTimer);
    }
}

impl<'a, A: Alarm<'a>> DoeTransport<'a> for EmulatedDoeTransport<'a, A> {
    fn set_tx_client(&self, client: &'a dyn DoeTransportTxClient<'a>) {
        self.tx_client.set(client);
    }

    fn set_rx_client(&self, client: &'a dyn DoeTransportRxClient) {
        self.rx_client.set(client);
    }

    fn set_rx_buffer(&self, rx_buf: &'static mut [u32]) {
        self.doe_data_buf.replace(rx_buf);
    }

    fn max_data_object_size(&self) -> usize {
        self.doe_data_buf_len
    }

    fn enable(&self) {
        self.state.set(DoeMboxState::RxWait);
    }

    fn disable(&self) {
        self.state.set(DoeMboxState::Idle);
    }

    fn transmit(&self, tx_buf: impl Iterator<Item = u32>, len_dw: usize) -> Result<(), ErrorCode> {
        if len_dw > self.max_data_object_size() {
            return Err(ErrorCode::SIZE);
        }

        let doe_buf = match self.doe_data_buf.take() {
            Some(buf) => buf,
            None => {
                debug!("DOE_MBOX_DRIVER: Error! No DOE data buffer available. This should not happen in normal operation.");
                return Err(ErrorCode::FAIL);
            }
        };

        doe_buf.fill(0);

        for (i, word) in tx_buf.enumerate().take(len_dw) {
            doe_buf[i] = word;
        }

        self.doe_data_buf.replace(doe_buf);

        // Set data len and data ready in the status register
        self.registers.doe_mbox_dlen.set(len_dw as u32);

        if let Some(_client) = self.tx_client.get() {
            // hold on to the client buffer until send_done is called
            self.state.set(DoeMboxState::TxInProgress);
            // In real hardware, this would be asynchronous. Here, we defer the send_done callback
            // to emulate hardware behavior by scheduling it via an alarm.
            self.schedule_send_done();
        } else {
            // We don't have a client to notify, so we just set the status data ready for the next read
            self.registers
                .doe_mbox_status
                .write(DoeMboxStatus::DataReady::SET);
        }

        Ok(())
    }
}
