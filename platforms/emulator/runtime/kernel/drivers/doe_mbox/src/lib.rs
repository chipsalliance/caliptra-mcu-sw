// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use doe_transport::hil::{DoeTransport, DoeTransportRxClient, DoeTransportTxClient};

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use core::cell::Cell;
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks, Time};
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
    RxWait,       // Driver owns DOE SRAM buffer, waiting for data.
    RxInProgress, // Client owns DOE SRAM buffer, waiting for set_rx_buffer() call.
    ReadyForTx,   // Driver owns DOE SRAM buffer, ready to send data.
    TxInProgress, // Driver owns the Client TX buffer and DOE SRAM buffer, waiting for send_done() call.
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
    doe_data_buf: TakeCell<'static, [u32]>,
    doe_data_buf_len: usize,

    // Buffer to hold the client data object.
    client_buf: TakeCell<'static, [u8]>,

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
    const DEFER_SEND_DONE_TICKS: u32 = 10;

    // TODO: The DOE instance should generate the response within 1 second.
    // This timeout may need to be less than 1 second and need to adjusted.
    // Also, see if needs to be commonly defined in a shared location.
    const RESPONSE_TIMEOUT_MS: u32 = 1000;

    pub fn new(
        base: StaticRef<DoeMbox>,
        alarm: &'a MuxAlarm<'a, A>,
    ) -> EmulatedDoeTransport<'a, A> {
        let len = base.doe_mbox_sram.len();

        let static_doe_data_buf = doe_mbox_sram_static_ref(len);

        EmulatedDoeTransport {
            registers: base,
            tx_client: OptionalCell::empty(),
            rx_client: OptionalCell::empty(),
            doe_data_buf: TakeCell::new(static_doe_data_buf),
            doe_data_buf_len: len,
            client_buf: TakeCell::empty(),
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

    fn start_response_timeout(&self) {
        self.timer_mode.set(TimerMode::ResponseTimeout);
        // Set an alarm to trigger after RESPONSE_TIMEOUT_MS milliseconds
        let now = self.alarm.now();
        let delta = self.alarm.ticks_from_ms(Self::RESPONSE_TIMEOUT_MS);
        self.alarm.set_alarm(now, delta);
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
            // Write 1 to clear the RESET_REQ event
            self.registers
                .doe_mbox_event
                .modify(DoeMboxEvent::ResetReq::SET);
            if self.state.get() != DoeMboxState::RxWait {
                // If client/driver buffer is still in use, we cannot reset.
                // Defer the reset until the buffers are returned to owners.
                self.pending_reset.set(true);
            } else {
                // Reset the DOE Mbox status and state
                self.reset_state();
            }
            return;
        }

        // 2. Only handle DATA_READY if in RxWait state
        if event.is_set(DoeMboxEvent::DataReady) {
            if self.state.get() != DoeMboxState::RxWait {
                // Not currently waiting for data, ignore DATA_READY
                return;
            }

            // Clear the DATA_READY event, writing 1 to the event register
            self.registers
                .doe_mbox_event
                .modify(DoeMboxEvent::DataReady::SET);

            // Start the response timeout timer
            self.start_response_timeout();

            let data_len = self.registers.doe_mbox_dlen.get() as usize;
            // If the data length is not valid, set error bit
            if data_len > self.max_data_object_size() {
                self.registers
                    .doe_mbox_status
                    .write(DoeMboxStatus::Error::SET);
                return;
            }

            match self.doe_data_buf.take() {
                Some(rx_buf) => {
                    if let Some(client) = self.rx_client.get() {
                        self.state.set(DoeMboxState::RxInProgress);
                        client.receive(rx_buf, data_len);
                    } else {
                        // No client to receive data, just restore the buffer
                        self.doe_data_buf.replace(rx_buf);
                    }
                }
                None => {
                    // We don't have a buffer to receive data
                    // This should not happen in normal operation
                    panic!("DOE_MBOX_DRIVER: No RX buffer available");
                }
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
                self.registers
                    .doe_mbox_status
                    .write(DoeMboxStatus::Error::SET);
                debug!("DOE Mbox: Response timeout occurred");
                match self.state.get() {
                    DoeMboxState::RxInProgress | DoeMboxState::TxInProgress => {
                        // If we were in RxInProgress or TxInProgress state, we need to reset the state
                        self.pending_reset.set(true);
                    }
                    _ => {
                        // If we were in RxWait or ReadyForTx state, just reset to RxWait
                        self.pending_reset.set(false);
                        self.reset_state();
                    }
                }
            }
            TimerMode::SendDoneDefer => {
                self.tx_client.map(|client| {
                    if let Some(buf) = self.client_buf.take() {
                        client.send_done(buf, Ok(()));
                    } else {
                        panic!("DOE_MBOX_DRIVER: No client buffer available for send_done");
                    }
                    self.registers
                        .doe_mbox_status
                        .write(DoeMboxStatus::DataReady::SET);
                });
                if self.pending_reset.get() {
                    // If we were in TxInProgress state, we need to reset the state
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

impl<'a, A: Alarm<'a>> DoeTransport for EmulatedDoeTransport<'a, A> {
    fn set_tx_client(&self, client: &'a dyn DoeTransportTxClient) {
        self.tx_client.set(client);
    }

    fn set_rx_client(&self, client: &'a dyn DoeTransportRxClient) {
        self.rx_client.set(client);
    }

    fn set_rx_buffer(&self, rx_buf: &'static mut [u32]) {
        self.doe_data_buf.replace(rx_buf);
        if self.pending_reset.get() {
            // If we were waiting for a reset, reset the state now
            self.reset_state();
        } else {
            // Move to ReadyForTx state
            self.state.set(DoeMboxState::ReadyForTx);
        }
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

    // #[allow(clippy::manual_memcpy)]
    fn transmit(
        &self,
        doe_message: &'static mut [u8],
        message_len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if self.state.get() != DoeMboxState::ReadyForTx {
            debug!("DOE Mbox: Cannot transmit, not in ReadyForTx state");
            return Err((ErrorCode::FAIL, doe_message));
        }

        if message_len > self.max_data_object_size() {
            return Err((ErrorCode::SIZE, doe_message));
        }

        // Check if the tx buffer is available
        if self.doe_data_buf.is_none() {
            panic!("DOE_MBOX_DRIVER: No TX buffer available. This should not happen in normal operation.");
        }

        self.state.set(DoeMboxState::TxInProgress);

        // copy the header and payload into the tx buffer
        let tx_buf = self.doe_data_buf.take().unwrap();

        for (i, chunk) in doe_message.chunks(4).enumerate().take(message_len / 4) {
            let mut dword = [0u8; 4];
            dword[..chunk.len()].copy_from_slice(chunk);
            tx_buf[i] = u32::from_le_bytes(dword);
        }
        let data_len = message_len / 4; // Length in DWORDs

        // Replace the buffer with the new copied data
        self.doe_data_buf.replace(tx_buf);

        // Set data len and data ready in the status register
        self.registers.doe_mbox_dlen.set(data_len as u32);

        if let Some(_client) = self.tx_client.get() {
            // hold on to the client buffer until send_done is called
            self.client_buf.replace(doe_message);
            // In real hardware, this would be asynchronous. Here, we defer the send_done callback
            // to emulate hardware behavior by scheduling it via an alarm.
            self.schedule_send_done();
        } else {
            // We don't have a client to notify, so we just set the status data ready for the next read
            self.registers
                .doe_mbox_status
                .write(DoeMboxStatus::DataReady::SET);
            self.state.set(DoeMboxState::RxWait);
        }

        Ok(())
    }
}
