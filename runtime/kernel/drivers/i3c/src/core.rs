// Licensed under the Apache-2.0 license

// I2C / I3C driver for the https://github.com/chipsalliance/i3c-core chip.

use crate::hil::I3CTargetInfo;
use crate::hil::{RxClient, TxClient};
use caliptra_mcu_registers_generated::i3c::bits::{
    InterruptEnable, InterruptStatus, Status, StbyCrDeviceAddr,
};
use caliptra_mcu_registers_generated::i3c::regs::I3c;
use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use core::cell::Cell;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil::time::{Alarm, AlarmClient, Time};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::ErrorCode;
use tock_registers::{register_bitfields, LocalRegisterCopy};

pub const MDB_PENDING_READ_MCTP: u8 = 0xae;
/// TTI RX and TX data FIFO capacity: 64 DWORD entries.
pub const MAX_READ_WRITE_SIZE: usize = 256;
#[cfg(target_arch = "riscv32")]
const WRITE_DELAY_CYCLES: usize = 100;

register_bitfields! {
    u32,
    IbiDescriptor [
        Mdb OFFSET(24) NUMBITS(8) [],
        DataLength OFFSET(0) NUMBITS(8) [],
    ],
    RxDesc [
        Error OFFSET(28) NUMBITS(4) [],
        DataLength OFFSET(0) NUMBITS(16) [],
    ],
}

pub struct I3CCore<'a, A: Alarm<'a>> {
    registers: StaticRef<I3c>,
    tx_client: OptionalCell<&'a dyn TxClient>,
    rx_client: OptionalCell<&'a dyn RxClient>,

    // buffers data to be received from the controller when it issues a write to us
    rx_buffer: TakeCell<'static, [u8]>,

    // buffers data to be sent to the controller when it issues a read to us
    tx_buffer: TakeCell<'static, [u8]>,
    tx_buffer_idx: Cell<usize>,
    tx_buffer_size: Cell<usize>,

    // alarm conditions
    alarm: VirtualMuxAlarm<'a, A>,
    retry_outgoing_read: Cell<bool>,
    retry_incoming_write: Cell<bool>,
    pending_ibi: OptionalCell<(u8, u16)>,
    tx_desc_complete: Cell<bool>,
    max_read_len: Cell<usize>,
    max_write_len: Cell<usize>,
    deferred_call: DeferredCall,
}

impl<'a, A: Alarm<'a>> I3CCore<'a, A> {
    // how long to wait to retry
    // Setting this too low can cause the kernel to starve the user process as the kernel will be too busy
    // servicing the timers to allow the user process to make progress.
    const RETRY_WAIT_TICKS: u32 = 5000;

    pub fn new(base: StaticRef<I3c>, alarm: &'a MuxAlarm<'a, A>) -> Self {
        I3CCore {
            registers: base,
            tx_client: OptionalCell::empty(),
            rx_client: OptionalCell::empty(),
            rx_buffer: TakeCell::empty(),
            tx_buffer: TakeCell::empty(),
            tx_buffer_idx: Cell::new(0),
            tx_buffer_size: Cell::new(0),
            alarm: VirtualMuxAlarm::new(alarm),
            retry_outgoing_read: Cell::new(false),
            retry_incoming_write: Cell::new(false),
            pending_ibi: OptionalCell::empty(),
            tx_desc_complete: Cell::new(false),
            max_read_len: Cell::new(MAX_READ_WRITE_SIZE),
            max_write_len: Cell::new(MAX_READ_WRITE_SIZE),
            deferred_call: DeferredCall::new(),
        }
    }

    /// Sets the maximum bytes returned to the controller for one private read.
    pub fn set_max_read_len(&self, max_read_len: usize) {
        assert!((1..=MAX_READ_WRITE_SIZE).contains(&max_read_len));
        self.max_read_len.set(max_read_len);
    }

    /// Sets the maximum bytes accepted from the controller for one private write.
    pub fn set_max_write_len(&self, max_write_len: usize) {
        assert!((1..=MAX_READ_WRITE_SIZE).contains(&max_write_len));
        self.max_write_len.set(max_write_len);
    }

    pub fn init(&'static self) {
        // Most of the I3C setup is done by the ROM.
        self.alarm.setup();
        self.alarm.set_alarm_client(self);
        self.register();
    }

    pub fn enable_interrupts(&self) {
        caliptra_mcu_romtime::println!("[mcu-runtime-i3c] Enabling I3C interrupts");
        self.registers.tti_interrupt_enable.modify(
            InterruptEnable::RxDescStatEn::SET
                + InterruptEnable::IbiDoneEn::SET
                + InterruptEnable::TxDescCompleteEn::SET,
        );
    }

    pub fn disable_interrupts(&self) {
        caliptra_mcu_romtime::println!("[mcu-runtime-i3c] Disabling I3C interrupts");
        self.registers.tti_interrupt_enable.set(0);
    }

    pub fn handle_interrupt(&self) {
        let mut tti_interrupts = self.registers.tti_interrupt_status.extract();
        if tti_interrupts.get() != 0 {
            if tti_interrupts.read(InterruptStatus::IbiDone) != 0 {
                // we have to read the IBI status to clear the interrupt
                let ibi_status = self.registers.tti_status.read(Status::LastIbiStatus);
                self.ibi_done(ibi_status);
            }
            if tti_interrupts.read(InterruptStatus::TxDescComplete) != 0 {
                self.registers
                    .tti_interrupt_status
                    .write(InterruptStatus::TxDescComplete::SET);
                self.tx_desc_complete.set(true);
                self.try_complete_tx();
            }
            // There is a pending Write Transaction. Software should read data from the RX Descriptor Queue and the RX Data Queue
            while tti_interrupts.read(InterruptStatus::RxDescStat) != 0 {
                if !self.handle_incoming_write() {
                    break;
                }
                tti_interrupts = self.registers.tti_interrupt_status.extract();
            }
        }
    }

    fn set_alarm(&self, ticks: u32) {
        let now = self.alarm.now();
        self.alarm.set_alarm(now, ticks.into());
    }

    // called when TTI has a private Write with data for us to grab
    // Returns false if we could not process the write (e.g., no buffer available)
    pub fn handle_incoming_write(&self) -> bool {
        self.retry_incoming_write.set(false);
        if self.rx_buffer.is_none() {
            self.rx_client.map(|client| {
                client.write_expected();
            });
        }

        if self.rx_buffer.is_none() {
            // try again later
            self.retry_incoming_write.set(true);
            self.set_alarm(Self::RETRY_WAIT_TICKS);
            return false;
        }

        let desc = self.registers.tti_rx_desc_queue_port.get();
        let desc = LocalRegisterCopy::<u32, RxDesc::Register>::new(desc);
        let len = desc.read(RxDesc::DataLength) as usize;
        if len == 0 {
            // we're done
            return false;
        }
        let rx_buffer = self.rx_buffer.take().unwrap();
        let valid = desc.read(RxDesc::Error) == 0
            && len <= rx_buffer.len()
            && len <= self.max_write_len.get();

        // Drain every word, including rejected packets, so the next descriptor
        // stays aligned with its data. Never deliver a truncated packet to the
        // transport: a coincidental PEC match could otherwise accept it.
        for i in (0..len).step_by(4) {
            let data = self.registers.tti_rx_data_port.get().to_le_bytes();
            if valid {
                let count = (len - i).min(4);
                rx_buffer[i..i + count].copy_from_slice(&data[..count]);
            }
        }

        if !valid {
            // Keep the receive buffer armed for the next valid packet.
            self.rx_buffer.put(Some(rx_buffer));
            return true;
        }

        self.rx_client.map(|client| {
            client.receive_write(rx_buffer, len);
        });
        true
    }

    // called when TTI wants us to send data for a private Read
    pub fn handle_outgoing_read(&self) {
        self.retry_outgoing_read.set(false);

        if self.tx_buffer.is_none() {
            // we have nothing to send, retry in a little while
            self.retry_outgoing_read.set(true);
            self.set_alarm(Self::RETRY_WAIT_TICKS);
            return;
        }

        let buf = self.tx_buffer.take().unwrap();
        let mut idx = self.tx_buffer_idx.replace(0);
        let size = self.tx_buffer_size.replace(0);
        if idx < size {
            self.registers
                .tti_tx_desc_queue_port
                .set((size - idx) as u32);
            while idx < size {
                let mut bytes = [0; 4];
                for b in bytes[0..4.min(size - idx)].iter_mut() {
                    *b = buf[idx];
                    idx += 1;
                }
                let word = u32::from_le_bytes(bytes);
                self.registers.tti_tx_data_port.set(word);
            }
        }
        // Keep the buffer until both the IBI and the controller's private read
        // complete. Returning it earlier lets the client fill the target TX
        // queue with later packets before this packet is consumed.

        // Give hardware time to finish buffering. Tock's host nop is a
        // panicking stub; memory-backed host tests do not need this delay.
        #[cfg(target_arch = "riscv32")]
        for _ in 0..WRITE_DELAY_CYCLES {
            rv32i::support::nop();
        }

        self.tx_buffer.put(Some(buf));
        // TODO: if no tx_client then we just drop the buffer?
    }

    fn deferred_done(&self) {
        if self.tx_buffer.is_none() {
            return;
        }
        self.tx_client.map(|client| {
            client.send_done(self.tx_buffer.take().unwrap(), Ok(()));
        });
    }

    fn try_complete_tx(&self) {
        if self.pending_ibi.is_none() && self.tx_desc_complete.get() && self.tx_buffer.is_some() {
            self.tx_desc_complete.set(false);
            self.deferred_call.set();
        }
    }

    fn send_ibi(&self, mdb: u8, len: u16) {
        if self.pending_ibi.is_some() {
            // we can only have one IBI pending at a time
            return;
        }
        // write the descriptor first
        self.registers
            .tti_tti_ibi_port
            .set((IbiDescriptor::Mdb.val(mdb as u32) + IbiDescriptor::DataLength.val(2)).into());

        // Note: we only write 2 bytes so that the IBI is <=4 bytes long so that
        // the controller can read it in one dword.
        self.registers.tti_tti_ibi_port.set(len.swap_bytes() as u32);
        self.pending_ibi.set((mdb, len));
    }

    fn ibi_done(&self, ibi_status: u32) {
        if let Some((mdb, len)) = self.pending_ibi.take() {
            // check if IBI was successful
            if ibi_status == 0 {
                self.try_complete_tx();
                // schedule a callback to handle any pending private reads
                self.set_alarm(Self::RETRY_WAIT_TICKS);
            } else {
                // re-send IBI
                self.send_ibi(mdb, len);
            }
        }
    }
}

impl<'a, A: Alarm<'a>> crate::hil::I3CTarget<'a> for I3CCore<'a, A> {
    fn set_tx_client(&self, client: &'a dyn TxClient) {
        self.tx_client.set(client)
    }

    fn set_rx_client(&self, client: &'a dyn RxClient) {
        self.rx_client.set(client)
    }

    fn set_rx_buffer(&self, rx_buf: &'static mut [u8]) {
        self.rx_buffer.replace(rx_buf);
    }

    fn transmit_read(
        &self,
        tx_buf: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        // The buffer remains owned until both the IBI and private read complete.
        if self.tx_buffer.is_some() || self.pending_ibi.is_some() {
            caliptra_mcu_romtime::println!("[mcu-runtime-i3c] transmit_read called but previous IBI still pending or tx_buffer in use: {} {}", self.tx_buffer.is_some(), self.pending_ibi.is_some());
            return Err((ErrorCode::BUSY, tx_buf));
        }
        if len == 0 || len > tx_buf.len() || len > self.max_read_len.get() {
            return Err((ErrorCode::SIZE, tx_buf));
        }
        self.tx_desc_complete.set(false);
        self.tx_buffer.replace(tx_buf);
        self.tx_buffer_idx.set(0);
        self.tx_buffer_size.set(len);
        // TODO: check that this is for MCTP or something else
        // immediately send the read to the I3C target interface and send an IBI so the controller knows we have data
        self.handle_outgoing_read();
        // send the length as part of the IBI
        self.send_ibi(MDB_PENDING_READ_MCTP, len as u16);
        Ok(())
    }

    fn enable(&self) {
        self.enable_interrupts()
    }

    fn disable(&self) {
        self.disable_interrupts()
    }

    fn get_device_info(&self) -> I3CTargetInfo {
        let dynamic_addr = if self
            .registers
            .stdby_ctrl_mode_stby_cr_device_addr
            .read(StbyCrDeviceAddr::DynamicAddrValid)
            == 1
        {
            Some(
                self.registers
                    .stdby_ctrl_mode_stby_cr_device_addr
                    .read(StbyCrDeviceAddr::DynamicAddr) as u8,
            )
        } else {
            None
        };
        let static_addr = if self
            .registers
            .stdby_ctrl_mode_stby_cr_device_addr
            .read(StbyCrDeviceAddr::StaticAddrValid)
            == 1
        {
            Some(
                self.registers
                    .stdby_ctrl_mode_stby_cr_device_addr
                    .read(StbyCrDeviceAddr::StaticAddr) as u8,
            )
        } else {
            None
        };
        I3CTargetInfo {
            static_addr,
            dynamic_addr,
            max_read_len: self.max_read_len.get(),
            max_write_len: self.max_write_len.get(),
        }
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for I3CCore<'a, A> {
    fn alarm(&self) {
        if self.retry_outgoing_read.get() {
            self.handle_outgoing_read();
        }
        if self.retry_incoming_write.get() {
            self.handle_interrupt();
        }
    }
}

impl<'a, A: Alarm<'a>> DeferredCallClient for I3CCore<'a, A> {
    fn handle_deferred_call(&self) {
        self.deferred_done();
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}

#[cfg(all(test, not(target_arch = "riscv32")))]
#[path = "tests.rs"]
mod tests;
