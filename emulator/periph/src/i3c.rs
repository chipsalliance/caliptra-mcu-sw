/*++
Licensed under the Apache-2.0 license.
File Name:
    i3c.rs
Abstract:
    File contains I3C peripheral implementation.
--*/

use crate::i3c_protocol::{I3cController, I3cTarget, I3cTcriResponseXfer, ResponseDescriptor};
use emulator_bus::{Clock, Timer};
use emulator_cpu::Irq;
use emulator_registers_generated::i3c::I3cPeripheral;
use emulator_types::{RvData, RvSize};
use registers_generated::i3c::bits::{ExtcapHeader, StbyCrCapabilities, TtiQueueSize};
use std::collections::VecDeque;
use zerocopy::FromBytes;

pub struct I3c {
    /// Timer
    timer: Timer,
    /// I3C target abstraction
    i3c_target: I3cTarget,
    /// RX Command in u32
    tti_rx_desc_queue_raw: VecDeque<u32>,
    /// RX DATA in u8
    tti_rx_data_raw: VecDeque<u8>,
    /// TX Command in u32
    tti_tx_desc_queue_raw: VecDeque<u32>,
    /// TX DATA in u32
    tti_tx_data_raw: VecDeque<u8>,
    /// Error interrupt
    _error_irq: Irq,
    /// Notification interrupt
    _notif_irq: Irq,
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
        let i3c_target = I3cTarget::default();

        controller.attach_target(i3c_target.clone()).unwrap();
        let timer = Timer::new(clock);
        timer.schedule_poll_in(Self::HCI_TICKS);

        Self {
            i3c_target,
            timer,
            tti_rx_desc_queue_raw: VecDeque::new(),
            tti_rx_data_raw: VecDeque::new(),
            tti_tx_desc_queue_raw: VecDeque::new(),
            tti_tx_data_raw: VecDeque::new(),
            _error_irq: error_irq,
            _notif_irq: notif_irq,
        }
    }

    fn write_tx_data_into_target(&mut self) {
        if !self.tti_tx_desc_queue_raw.is_empty() {
            let resp_desc = ResponseDescriptor::read_from_bytes(
                &self.tti_tx_desc_queue_raw[0].to_ne_bytes()[..],
            )
            .unwrap();
            let data_size = resp_desc.data_length().into();
            if self.tti_tx_data_raw.len() >= data_size {
                let resp = I3cTcriResponseXfer {
                    resp: resp_desc,
                    data: self.tti_tx_data_raw.drain(..data_size).collect(),
                };
                self.i3c_target.set_response(resp);
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
            self.tti_rx_data_raw.extend(data);
        }
    }
}

impl I3cPeripheral for I3c {
    fn read_i3c_base_hci_version(&mut self, _size: RvSize) -> RvData {
        RvData::from(Self::HCI_VERSION)
    }

    fn read_i3c_ec_stdby_ctrl_mode_stby_cr_capabilities(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, StbyCrCapabilities::Register> {
        emulator_bus::ReadWriteRegister::new(StbyCrCapabilities::TargetXactSupport.val(1).value)
    }

    fn read_i3c_ec_tti_extcap_header(
        &mut self,
        _size: RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, ExtcapHeader::Register> {
        emulator_bus::ReadWriteRegister::new(ExtcapHeader::CapId.val(0xc4).value)
    }

    fn read_i3c_ec_tti_rx_desc_queue_port(&mut self, _size: RvSize) -> u32 {
        self.tti_rx_desc_queue_raw.pop_front().unwrap_or(0)
    }

    fn read_i3c_ec_tti_rx_data_port(&mut self, size: RvSize) -> u32 {
        match size {
            RvSize::Byte => self.tti_rx_data_raw.pop_front().unwrap_or(0).into(),
            RvSize::HalfWord => {
                let mut data = (self.tti_rx_data_raw.pop_front().unwrap_or(0) as u32) << 8;
                data |= self.tti_rx_data_raw.pop_front().unwrap_or(0) as u32;
                data
            }
            RvSize::Word => {
                let mut data = (self.tti_rx_data_raw.pop_front().unwrap_or(0) as u32) << 24;
                data |= (self.tti_rx_data_raw.pop_front().unwrap_or(0) as u32) << 16;
                data |= (self.tti_rx_data_raw.pop_front().unwrap_or(0) as u32) << 8;
                data |= self.tti_rx_data_raw.pop_front().unwrap_or(0) as u32;
                data
            }
            RvSize::Invalid => {
                panic!("Invalid size")
            }
        }
    }

    fn write_i3c_ec_tti_tx_desc_queue_port(&mut self, _size: RvSize, val: u32) {
        self.tti_tx_desc_queue_raw.push_back(val);
        self.write_tx_data_into_target();
    }

    fn write_i3c_ec_tti_tx_data_port(&mut self, size: RvSize, val: u32) {
        let to_append = val.to_le_bytes();
        for byte in &to_append[..size.into()] {
            self.tti_tx_data_raw.push_back(*byte)
        }
        self.write_tx_data_into_target();
    }

    fn read_i3c_ec_tti_tti_queue_size(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<u32, TtiQueueSize::Register> {
        emulator_bus::ReadWriteRegister::new(
            (TtiQueueSize::RxDataBufferSize.val(5)
                + TtiQueueSize::TxDataBufferSize.val(5)
                + TtiQueueSize::RxDescBufferSize.val(5)
                + TtiQueueSize::TxDescBufferSize.val(5))
            .value,
        )
    }

    fn poll(&mut self) {
        self.read_rx_data_into_buffer();
        self.timer.schedule_poll_in(Self::HCI_TICKS);
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

        let mut bus = AutoRootBus::new(None, Some(i3c), None, None, None, None);
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
