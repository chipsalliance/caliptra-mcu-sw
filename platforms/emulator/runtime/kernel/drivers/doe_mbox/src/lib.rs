// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use doe_transport::hil::{DoeTransport, DoeTransportRxClient, DoeTransportTxClient, DOE_HDR_SIZE};

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use core::cell::Cell;
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks, Time};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::{debug, ErrorCode};
use registers_generated::doe_mbox::bits::{DoeMboxDataReady, DoeMboxStatus};
use registers_generated::doe_mbox::regs::DoeMbox;
use registers_generated::doe_mbox::DOE_MBOX_ADDR;

pub const DOE_MBOX_BASE: StaticRef<DoeMbox> =
    unsafe { StaticRef::new(DOE_MBOX_ADDR as *const DoeMbox) };

const DOE_MBOX_SRAM_ADDR: u32 = DOE_MBOX_ADDR + 0x1000; // SRAM offset from DOE Mbox base address

#[derive(Copy, Clone, Debug, PartialEq)]
enum DoeMboxState {
    Idle,
    RxWait,
    RxReceived,
    TxDeferred,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum TimerMode {
    NoTimer,
    ResponseTimeout,
    SendDoneDefer,
}

pub struct EmulatedDoeTransport<'a, A: Alarm<'a>> {
    registers: StaticRef<DoeMbox>,
    tx_client: OptionalCell<&'a dyn DoeTransportTxClient>,
    rx_client: OptionalCell<&'a dyn DoeTransportRxClient>,

    // Buffer to send/receive the DOE data object.
    doe_data_buf: TakeCell<'static, [u8]>,
    doe_data_buf_len: usize,

    // Buffer to hold the client data object.
    client_buf: TakeCell<'static, [u8]>,

    state: Cell<DoeMboxState>,
    timer_mode: Cell<TimerMode>,
    alarm: VirtualMuxAlarm<'a, A>,
}

fn doe_mbox_sram_static_ref(len: usize) -> &'static mut [u8] {
    // SAFETY: We assume the SRAM is initialized and the address is valid.
    // The length is provided by the caller and should match the actual SRAM size.
    unsafe { core::slice::from_raw_parts_mut(DOE_MBOX_SRAM_ADDR as *mut u8, len) }
}

impl<'a, A: Alarm<'a>> EmulatedDoeTransport<'a, A> {
    // This is just to add a delay calling `send_done` to emulate the hardware behavior.
    // Number of ticks to defer send_done
    const DEFER_SEND_DONE_TICKS: u32 = 10;

    // TODO: The DOE instance should generate the response within 1 second.
    // This timeout may need to be less than 1 second and need to adjusted.
    // Also, see if needs to be commonly defined in a shared location.
    const RESPONSE_TIMEOUT_MS: u32 = 1000;

    pub fn new(
        base: StaticRef<DoeMbox>,
        alarm: &'a MuxAlarm<'a, A>,
    ) -> EmulatedDoeTransport<'a, A> {
        let len = base.doe_mbox_sram.len() * core::mem::size_of::<u32>();

        let static_doe_data_buf = doe_mbox_sram_static_ref(len);

        EmulatedDoeTransport {
            registers: base,
            tx_client: OptionalCell::empty(),
            rx_client: OptionalCell::empty(),
            doe_data_buf: TakeCell::new(static_doe_data_buf),
            doe_data_buf_len: len,
            client_buf: TakeCell::empty(),
            state: Cell::new(DoeMboxState::Idle),
            timer_mode: Cell::new(TimerMode::NoTimer),
            alarm: VirtualMuxAlarm::new(alarm),
        }
    }

    pub fn init(&'static self) {
        self.alarm.setup();
        self.alarm.set_alarm_client(self);
        self.state.set(DoeMboxState::RxWait);
    }

    fn schedule_send_done(&self) {
        self.timer_mode.set(TimerMode::SendDoneDefer);
        self.state.set(DoeMboxState::TxDeferred);
        let now = self.alarm.now();
        self.alarm
            .set_alarm(now, (Self::DEFER_SEND_DONE_TICKS).into());
    }

    fn start_response_timeout(&self) {
        self.timer_mode.set(TimerMode::ResponseTimeout);
        // Set an alarm to trigger after RESPONSE_TIMEOUT_MS milliseconds
        let now = self.alarm.now();
        let delta = self.alarm.ticks_from_ms(Self::RESPONSE_TIMEOUT_MS);
        self.alarm.set_alarm(now, delta);
    }

    pub fn handle_interrupt(&self) {
        if self.state.get() != DoeMboxState::RxWait {
            return;
        }

        let data_ready = self.registers.doe_mbox_data_ready.extract();
        if !data_ready.is_set(DoeMboxDataReady::DataReady) {
            return;
        }

        // Clear any existing status flags
        self.registers
            .doe_mbox_status
            .write(DoeMboxStatus::DataReady::CLEAR);
        self.registers
            .doe_mbox_status
            .write(DoeMboxStatus::Error::CLEAR);
        self.start_response_timeout();

        let data_len = self.registers.doe_mbox_dlen.get() as usize;
        if data_len > self.max_data_object_size() {
            self.registers
                .doe_mbox_status
                .write(DoeMboxStatus::Error::SET);
            debug!("DOE Mbox Intr: Data length exceeds maximum size");
            return;
        }

        match self.doe_data_buf.take() {
            Some(rx_buf) => {
                if let Some(client) = self.rx_client.get() {
                    client.receive(rx_buf, data_len);
                    self.state.set(DoeMboxState::RxReceived);
                }
            }
            None => {
                self.registers
                    .doe_mbox_status
                    .write(DoeMboxStatus::Error::SET);
                debug!("DOE Mbox intr: No RX buffer available");
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
            TimerMode::ResponseTimeout => {
                if self.state.get() == DoeMboxState::RxReceived {
                    self.registers
                        .doe_mbox_status
                        .write(DoeMboxStatus::Error::SET);
                    debug!("DOE Mbox: Response timeout, resetting to RxWait");
                }
                // Always reset state to RxWait after timeout
                self.state.set(DoeMboxState::RxWait);
            }
            TimerMode::SendDoneDefer => {
                self.tx_client.map(|client| {
                    client.send_done(self.client_buf.take().unwrap(), Ok(()));
                });
                // After send_done, go back to RxWait
                self.state.set(DoeMboxState::RxWait);
            }
        }
        // Clear timer mode after handling
        self.timer_mode.set(TimerMode::NoTimer);
    }
}

impl<'a, A: Alarm<'a>> DoeTransport for EmulatedDoeTransport<'a, A> {
    fn set_tx_client(&self, client: &'a dyn DoeTransportTxClient) {
        self.tx_client.set(client);
    }

    fn set_rx_client(&self, client: &'a dyn DoeTransportRxClient) {
        self.rx_client.set(client);
    }

    fn set_rx_buffer(&self, rx_buf: &'static mut [u8]) {
        self.doe_data_buf.replace(rx_buf);
    }

    fn max_data_object_size(&self) -> usize {
        self.doe_data_buf_len
    }

    fn enable(&self) -> Result<(), ErrorCode> {
        self.state.set(DoeMboxState::RxWait);
        Ok(())
    }

    fn disable(&self) -> Result<(), ErrorCode> {
        self.state.set(DoeMboxState::Idle);
        Ok(())
    }

    fn transmit(
        &self,
        doe_hdr: [u8; DOE_HDR_SIZE],
        doe_payload: &'static mut [u8],
        payload_len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if self.state.get() != DoeMboxState::RxReceived {
            debug!("DOE Mbox: Cannot transmit, not in RxReceived state");
            return Err((ErrorCode::FAIL, doe_payload));
        }

        if DOE_HDR_SIZE + payload_len > self.max_data_object_size() {
            return Err((ErrorCode::SIZE, doe_payload));
        }

        // Check if the tx buffer is available
        if self.doe_data_buf.is_none() {
            return Err((ErrorCode::NOMEM, doe_payload));
        }

        // copy the header and payload into the tx buffer
        let tx_buf = self.doe_data_buf.take().unwrap();
        tx_buf[..DOE_HDR_SIZE].copy_from_slice(&doe_hdr[..]);
        tx_buf[DOE_HDR_SIZE..DOE_HDR_SIZE + payload_len].copy_from_slice(doe_payload);

        // Set data len and data ready in the status register
        self.registers
            .doe_mbox_dlen
            .set((DOE_HDR_SIZE + payload_len) as u32);
        self.registers
            .doe_mbox_status
            .write(DoeMboxStatus::DataReady::SET);

        if let Some(_client) = self.tx_client.get() {
            // hold on to the client buffer until send_done is called
            self.client_buf.replace(doe_payload);
            // In real hardware, this would be asynchronous. Here, we defer the send_done callback
            // to emulate hardware behavior by scheduling it via an alarm.
            self.schedule_send_done();
        }

        Ok(())
    }
}
