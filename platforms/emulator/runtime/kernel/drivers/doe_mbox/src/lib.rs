// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use doe_transport::hil::{DoeTransport, DoeTransportRxClient, DoeTransportTxClient, DOE_HDR_SIZE};

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use core::cell::Cell;
use kernel::hil::time::{Alarm, AlarmClient, Time};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::{debug, ErrorCode};
use registers_generated::doe_mbox::bits::{DoeMboxDataReady, DoeMboxStatus};
use registers_generated::doe_mbox::regs::DoeMbox;

pub const DOE_MAX_DATA_OBJECT_SIZE: usize = 256; // arbitrary, adjust as needed

#[derive(Copy, Clone, Debug, PartialEq)]
enum DoeMboxState {
    Off,
    Tx,
    Rx,
}

pub struct EmulatedDoeTransport<'a, A: Alarm<'a>> {
    registers: StaticRef<DoeMbox>,
    tx_client: OptionalCell<&'a dyn DoeTransportTxClient>,
    rx_client: OptionalCell<&'a dyn DoeTransportRxClient>,

    // Buffer to receive the data object.
    rx_buffer: TakeCell<'static, [u8]>,

    // Buffer to hold the transmitted data object.
    tx_buffer: TakeCell<'static, [u8]>,

    // Flag to indicate if send_done should be scheduled.
    schedule_tx_done: Cell<bool>,

    state: Cell<DoeMboxState>,
    alarm: VirtualMuxAlarm<'a, A>,
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
        EmulatedDoeTransport {
            registers: base,
            tx_client: OptionalCell::empty(),
            rx_client: OptionalCell::empty(),
            rx_buffer: TakeCell::empty(),
            tx_buffer: TakeCell::empty(),
            state: Cell::new(DoeMboxState::Off),
            alarm: VirtualMuxAlarm::new(alarm),
            schedule_tx_done: Cell::new(false),
        }
    }

    pub fn init(&'static self) -> Result<(), ErrorCode> {
        self.alarm.setup();
        self.alarm.set_alarm_client(self);
        self.state.set(DoeMboxState::Rx);
        Ok(())
    }

    fn schedule_send_done(&self) {
        self.schedule_tx_done.set(true);
        let now = self.alarm.now();
        self.alarm
            .set_alarm(now, (Self::DEFER_SEND_DONE_TICKS).into());
    }

    pub fn handle_interrupt(&self) {
        if self.state.get() != DoeMboxState::Rx {
            // Ignore interrupt if not in Rx state
            return;
        }

        let data_ready = self.registers.doe_mbox_data_ready.extract();
        if data_ready.is_set(DoeMboxDataReady::DataReady) {
            // Clear DataReady and Error flags
            self.registers
                .doe_mbox_status
                .write(DoeMboxStatus::DataReady::CLEAR);
            self.registers
                .doe_mbox_status
                .write(DoeMboxStatus::Error::CLEAR);

            let data_len = self.registers.doe_mbox_dlen.get() as usize;
            if data_len > self.max_data_object_size() {
                self.registers
                    .doe_mbox_status
                    .write(DoeMboxStatus::Error::SET);
                debug!("DOE Mbox Intr: Data length exceeds maximum size");
                return;
            }

            match self.rx_buffer.take() {
                Some(rx_buf) => {
                    if let Some(client) = self.rx_client.get() {
                        client.receive(rx_buf, data_len);
                        // After receiving, we can set the state to Tx to allow transmission
                        self.state.set(DoeMboxState::Tx);
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
}

impl<'a, A: Alarm<'a>> AlarmClient for EmulatedDoeTransport<'a, A> {
    fn alarm(&self) {
        if self.schedule_tx_done.get() {
            // If we are scheduled to send done, call the tx client
            if let Some(client) = self.tx_client.get() {
                // Emulate sending done
                if let Some(tx_buf) = self.tx_buffer.take() {
                    client.send_done(tx_buf, Ok(()));
                }
            }
            self.schedule_tx_done.set(false);
            self.state.set(DoeMboxState::Rx);
        }
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
        self.rx_buffer.replace(rx_buf);
    }

    fn max_data_object_size(&self) -> usize {
        todo!("Get max data size from configured mailbox sram size")
    }

    fn enable(&self) -> Result<(), ErrorCode> {
        self.state.set(DoeMboxState::Rx);
        Ok(())
    }

    fn disable(&self) -> Result<(), ErrorCode> {
        self.state.set(DoeMboxState::Off);
        Ok(())
    }

    fn transmit(
        &self,
        doe_hdr: &'static [u8; DOE_HDR_SIZE],
        doe_payload: &'static mut [u8],
        payload_len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        // todo!("Check if the state is valid for transmission");
        if self.state.get() != DoeMboxState::Tx {
            debug!("DOE Mbox: Cannot transmit, not in Tx state");
            return Err((ErrorCode::BUSY, doe_payload));
        }

        if DOE_HDR_SIZE + payload_len > self.max_data_object_size() {
            return Err((ErrorCode::SIZE, doe_payload));
        }

        // Check if the tx buffer is available
        if self.tx_buffer.is_none() {
            return Err((ErrorCode::NOMEM, doe_payload));
        }

        // copy the header and payload into the tx buffer
        let tx_buf = self.tx_buffer.take().unwrap();
        tx_buf[..DOE_HDR_SIZE].copy_from_slice(doe_hdr);
        tx_buf[DOE_HDR_SIZE..DOE_HDR_SIZE + payload_len].copy_from_slice(doe_payload);

        // Set data len and data ready in the status register
        self.registers
            .doe_mbox_dlen
            .set((DOE_HDR_SIZE + payload_len) as u32);
        self.registers
            .doe_mbox_status
            .write(DoeMboxStatus::DataReady::SET);

        if let Some(_client) = self.tx_client.get() {
            // In real hardware, this would be asynchronous. Here, we defer the send_done callback
            // to emulate hardware behavior by scheduling it via an alarm.
            self.schedule_send_done();
        }

        Ok(())
    }
}
