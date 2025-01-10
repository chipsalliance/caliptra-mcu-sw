/*++
Licensed under the Apache-2.0 license.
File Name:
    i3c.rs
Abstract:
    File contains I3C peripheral implementation.
--*/

use crate::i3c_protocol::{I3cController, I3cTarget, I3cTcriResponseXfer, ResponseDescriptor};
use crate::{DynamicI3cAddress, I3cIncomingCommandClient, IbiDescriptor, ReguDataTransferCommand};
use emulator_bus::{Clock, ReadWriteRegister, Timer};
use emulator_cpu::Irq;
use emulator_registers_generated::i3c::I3cPeripheral;
use emulator_types::{RvData, RvSize};
use registers_generated::i3c::bits::{
    ExtcapHeader, InterruptEnable, InterruptStatus, StbyCrCapabilities, StbyCrDeviceAddr,
    TtiQueueSize,
};
use std::collections::VecDeque;
use std::sync::Arc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use zerocopy::FromBytes;

struct PollScheduler {
    timer: Timer,
}

impl I3cIncomingCommandClient for PollScheduler {
    fn incoming(&self) {
        // trigger interrupt check next tick
        self.timer.schedule_poll_in(1);
    }
}

pub struct I3c {
    /// Timer
    timer: Timer,
    /// I3C target abstraction
    i3c_target: I3cTarget,
    /// RX Command in u32
    tti_rx_desc_queue_raw: VecDeque<u32>,
    /// RX DATA in u8
    tti_rx_data_raw: VecDeque<Vec<u8>>,
    /// RX DATA currently being read from driver
    tti_rx_current: VecDeque<u8>,
    /// TX Command in u32
    tti_tx_desc_queue_raw: VecDeque<u32>,
    /// TX DATA in u8
    tti_tx_data_raw: VecDeque<Vec<u8>>,
    /// IBI buffer
    tti_ibi_buffer: Vec<u8>,
    /// Error interrupt
    _error_irq: Irq,
    /// Notification interrupt
    notif_irq: Irq,

    interrupt_status: ReadWriteRegister<u32, InterruptStatus::Register>,
    interrupt_enable: ReadWriteRegister<u32, InterruptEnable::Register>,
}

impl I3c {
    const HCI_VERSION: u32 = 0x120;
    const HCI_TICKS: u64 = 1000;

    pub fn new(
        clock: &Clock,
        controller: &mut I3cController,
        error_irq: Irq,
        notif_irq: Irq,
    ) -> Self {
        let mut i3c_target = I3cTarget::default();

        controller.attach_target(i3c_target.clone()).unwrap();
        let timer = Timer::new(clock);
        timer.schedule_poll_in(Self::HCI_TICKS);
        let poll_scheduler = PollScheduler {
            timer: timer.clone(),
        };
        i3c_target.set_incoming_command_client(Arc::new(poll_scheduler));

        Self {
            i3c_target,
            timer,
            tti_rx_desc_queue_raw: VecDeque::new(),
            tti_rx_data_raw: VecDeque::new(),
            tti_rx_current: VecDeque::new(),
            tti_tx_desc_queue_raw: VecDeque::new(),
            tti_tx_data_raw: VecDeque::new(),
            tti_ibi_buffer: vec![],
            _error_irq: error_irq,
            notif_irq,
            interrupt_status: ReadWriteRegister::new(0),
            interrupt_enable: ReadWriteRegister::new(0),
        }
    }

    pub fn get_dynamic_address(&self) -> Option<DynamicI3cAddress> {
        self.i3c_target.get_address()
    }

    fn write_tx_data_into_target(&mut self) {
        if !self.tti_tx_desc_queue_raw.is_empty() {
            let resp_desc = ResponseDescriptor::read_from_bytes(
                &self.tti_tx_desc_queue_raw[0].to_le_bytes()[..],
            )
            .unwrap();
            let data_size = resp_desc.data_length().into();
            if let Some(_data) = self.tti_tx_data_raw.front() {
                if self.tti_tx_data_raw[0].len() >= data_size {
                    self.tti_tx_desc_queue_raw.pop_front();
                    let resp = I3cTcriResponseXfer {
                        resp: resp_desc,
                        data: self.tti_tx_data_raw.pop_front().unwrap(),
                    };
                    self.i3c_target.set_response(resp);
                }
            }
        }
    }

    fn read_rx_data_into_buffer(&mut self) {
        if let Some(xfer) = self.i3c_target.read_command() {
            let cmd: u64 = xfer.cmd.into();
            let data = xfer.data;
            self.tti_rx_desc_queue_raw
                .push_back((cmd & 0xffff_ffff) as u32);
            self.tti_rx_desc_queue_raw
                .push_back(((cmd >> 32) & 0xffff_ffff) as u32);
            self.tti_rx_data_raw.push_back(data);
        }
    }

    fn check_interrupts(&mut self) {
        // TODO: implement the timeout interrupts

        // Set TxDescStat interrupt if there is a pending Read transaction (i.e., data needs to be written to the tx registers)
        let pending_read = self
            .tti_rx_desc_queue_raw
            .front()
            .map(|x| {
                ReguDataTransferCommand::read_from_bytes(&(*x as u64).to_le_bytes())
                    .unwrap()
                    .rnw()
                    == 1
            })
            .unwrap_or(false);
        self.interrupt_status.reg.modify(if pending_read {
            InterruptStatus::TxDescStat::SET
        } else {
            InterruptStatus::TxDescStat::CLEAR
        });

        // Set RxDescStat interrupt if there is a pending write (i.e., data to read from rx registers)
        self.interrupt_status
            .reg
            .modify(if self.tti_rx_desc_queue_raw.is_empty() {
                InterruptStatus::RxDescStat::CLEAR
            } else {
                InterruptStatus::RxDescStat::SET
            });

        self.notif_irq
            .set_level(self.interrupt_status.reg.any_matching_bits_set(
                InterruptStatus::RxDescStat::SET
                    + InterruptStatus::TxDescStat::SET
                    + InterruptStatus::RxDescTimeout::SET
                    + InterruptStatus::TxDescTimeout::SET,
            ));
    }

    // check if there area valid IBI descriptors and messages
    fn check_ibi_buffer(&mut self) {
        loop {
            if self.tti_ibi_buffer.len() <= 4 {
                return;
            }

            let desc = IbiDescriptor::read_from_bytes(&self.tti_ibi_buffer[0..4]).unwrap();
            let len = desc.data_length() as usize;
            if self.tti_ibi_buffer.len() < len + 4 {
                // wait for more data
                return;
            }
            // we only need the first byte, which is the MDB.
            // TODO: handle more than the MDB?
            // Drain IBI descriptor size + 4 bytes (MDB)
            self.i3c_target.send_ibi(self.tti_ibi_buffer[4]);
            self.tti_ibi_buffer.drain(0..(len + 4).next_multiple_of(4));
        }
    }
}

impl I3cPeripheral for I3c {
    fn read_i3c_base_hci_version(&mut self, _size: RvSize) -> RvData {
        RvData::from(Self::HCI_VERSION)
    }

    fn read_i3c_ec_tti_interrupt_enable(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::InterruptEnable::Register,
    > {
        self.interrupt_enable.clone()
    }

    fn read_i3c_ec_tti_interrupt_status(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::i3c::bits::InterruptStatus::Register,
    > {
        self.interrupt_status.clone()
    }

    fn write_i3c_ec_tti_interrupt_status(
        &mut self,
        _size: emulator_types::RvSize,
        val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::InterruptStatus::Register,
        >,
    ) {
        let current = self.interrupt_status.reg.get();
        let new = val.reg.get();
        // clear the interrupts that are set
        self.interrupt_status.reg.set(current & !new);
        self.check_interrupts();
    }

    fn write_i3c_ec_tti_interrupt_enable(
        &mut self,
        _size: emulator_types::RvSize,
        val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::i3c::bits::InterruptEnable::Register,
        >,
    ) {
        self.interrupt_enable.reg.set(val.reg.get());
    }

    fn write_i3c_ec_tti_tti_ibi_port(
        &mut self,
        size: emulator_types::RvSize,
        val: emulator_types::RvData,
    ) {
        match size {
            RvSize::Byte => {
                self.tti_ibi_buffer.push(val as u8);
            }
            RvSize::HalfWord => {
                let val = val as u16;
                self.tti_ibi_buffer.push(val as u8);
                self.tti_ibi_buffer.push((val >> 8) as u8);
            }
            RvSize::Word => {
                self.tti_ibi_buffer
                    .extend_from_slice(val.to_le_bytes().as_ref());
            }
            RvSize::Invalid => {
                panic!("Invalid size")
            }
        }
        self.check_ibi_buffer();
    }

    fn read_i3c_ec_stdby_ctrl_mode_stby_cr_capabilities(
        &mut self,
        _size: RvSize,
    ) -> ReadWriteRegister<u32, StbyCrCapabilities::Register> {
        ReadWriteRegister::new(StbyCrCapabilities::TargetXactSupport.val(1).value)
    }

    fn read_i3c_ec_stdby_ctrl_mode_stby_cr_device_addr(
        &mut self,
        _size: RvSize,
    ) -> ReadWriteRegister<u32, StbyCrDeviceAddr::Register> {
        let val = match self.i3c_target.get_address() {
            Some(addr) => {
                StbyCrDeviceAddr::DynamicAddr.val(addr.into())
                    + StbyCrDeviceAddr::DynamicAddrValid::SET
            }
            None => StbyCrDeviceAddr::StaticAddr.val(0x3d) + StbyCrDeviceAddr::StaticAddrValid::SET,
        };
        ReadWriteRegister::new(val.value)
    }

    fn read_i3c_ec_tti_extcap_header(
        &mut self,
        _size: RvSize,
    ) -> ReadWriteRegister<u32, ExtcapHeader::Register> {
        ReadWriteRegister::new(ExtcapHeader::CapId.val(0xc4).value)
    }

    fn read_i3c_ec_tti_rx_desc_queue_port(&mut self, _size: RvSize) -> u32 {
        if self.tti_rx_desc_queue_raw.len() & 1 == 0 {
            // only replace the data every other read since the descriptor is 64 bits
            self.tti_rx_current = self.tti_rx_data_raw.pop_front().unwrap_or_default().into();
        }
        self.tti_rx_desc_queue_raw.pop_front().unwrap_or(0)
    }

    fn read_i3c_ec_tti_rx_data_port(&mut self, size: RvSize) -> u32 {
        match size {
            RvSize::Byte => self.tti_rx_current.pop_front().unwrap_or(0) as u32,
            RvSize::HalfWord => {
                let mut data = (self.tti_rx_current.pop_front().unwrap_or(0) as u32) << 8;
                data |= self.tti_rx_current.pop_front().unwrap_or(0) as u32;
                data
            }
            RvSize::Word => {
                let mut data = self.tti_rx_current.pop_front().unwrap_or(0) as u32;
                data |= (self.tti_rx_current.pop_front().unwrap_or(0) as u32) << 8;
                data |= (self.tti_rx_current.pop_front().unwrap_or(0) as u32) << 16;
                data |= (self.tti_rx_current.pop_front().unwrap_or(0) as u32) << 24;
                data
            }
            RvSize::Invalid => {
                panic!("Invalid size")
            }
        }
    }

    fn write_i3c_ec_tti_tx_desc_queue_port(&mut self, _size: RvSize, val: u32) {
        self.tti_tx_desc_queue_raw.push_back(val);
        self.tti_tx_data_raw.push_back(vec![]);
        self.write_tx_data_into_target();
    }

    fn write_i3c_ec_tti_tx_data_port(&mut self, size: RvSize, val: u32) {
        let to_append = val.to_le_bytes();
        let idx = self.tti_tx_data_raw.len() - 1;
        for byte in &to_append[..size.into()] {
            self.tti_tx_data_raw[idx].push(*byte);
        }
        self.write_tx_data_into_target();
    }

    fn read_i3c_ec_tti_tti_queue_size(
        &mut self,
        _size: RvSize,
    ) -> ReadWriteRegister<u32, TtiQueueSize::Register> {
        ReadWriteRegister::new(
            (TtiQueueSize::RxDataBufferSize.val(5)
                + TtiQueueSize::TxDataBufferSize.val(5)
                + TtiQueueSize::RxDescBufferSize.val(5)
                + TtiQueueSize::TxDescBufferSize.val(5))
            .value,
        )
    }

    fn poll(&mut self) {
        self.check_interrupts();
        self.read_rx_data_into_buffer();
        self.write_tx_data_into_target();
        self.timer.schedule_poll_in(Self::HCI_TICKS);

        if cfg!(feature = "test-i3c-constant-writes") {
            static mut COUNTER: u32 = 0;
            // ensure there are 10 writes queued
            if self.tti_rx_desc_queue_raw.is_empty() && unsafe { COUNTER } < 10 {
                unsafe {
                    COUNTER += 1;
                }
                self.tti_rx_desc_queue_raw.push_back(100 << 16);
                self.tti_rx_desc_queue_raw.push_back(unsafe { COUNTER });
                self.tti_rx_data_raw.push_back(vec![0xff; 100]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i3c_protocol::{
        DynamicI3cAddress, I3cTcriCommand, I3cTcriCommandXfer, ImmediateDataTransferCommand,
    };
    use emulator_bus::Bus;
    use emulator_cpu::Pic;
    use emulator_registers_generated::root_bus::AutoRootBus;
    use emulator_types::RvAddr;

    const TTI_RX_DESC_QUEUE_PORT: RvAddr = 0x1dc;

    #[test]
    fn receive_i3c_cmd() {
        let clock = Clock::new();
        let pic = Pic::new();
        let error_irq = pic.register_irq(17);
        let notif_irq = pic.register_irq(18);
        let mut i3c_controller = I3cController::default();
        let mut i3c = Box::new(I3c::new(&clock, &mut i3c_controller, error_irq, notif_irq));

        assert_eq!(
            i3c.read_i3c_base_hci_version(RvSize::Word),
            I3c::HCI_VERSION
        );

        let cmd_bytes: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
        let cmd = I3cTcriCommandXfer {
            cmd: I3cTcriCommand::Immediate(
                ImmediateDataTransferCommand::read_from_bytes(&cmd_bytes[..]).unwrap(),
            ),
            data: Vec::new(),
        };
        i3c_controller
            .tcri_send(DynamicI3cAddress::new(8).unwrap(), cmd)
            .unwrap();

        let mut bus = AutoRootBus::new(
            vec![],
            Some(i3c),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        for _ in 0..10000 {
            clock.increment_and_process_timer_actions(1, &mut bus);
        }

        assert_eq!(
            bus.read(
                RvSize::Word,
                registers_generated::i3c::I3C_CSR_ADDR + TTI_RX_DESC_QUEUE_PORT
            )
            .unwrap(),
            1
        );
    }
}
