// Licensed under the Apache-2.0 license

// I2C / I3C driver for the https://github.com/chipsalliance/i3c-core chip.

use crate::hil::I3CTargetInfo;
use crate::hil::{RxClient, TxClient};
use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use core::cell::Cell;
use kernel::hil::time::{Alarm, AlarmClient, Time};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::{debug, ErrorCode};
use registers_generated::i3c::bits::HcControl::{BusEnable, ModeSelector};
use registers_generated::i3c::bits::{
    InterruptEnable, InterruptStatus, QueueThldCtrl, RingHeadersSectionOffset, StbyCrCapabilities,
    StbyCrControl, StbyCrDeviceAddr, StbyCrDeviceChar, TtiQueueThldCtrl,
};
use registers_generated::i3c::regs::I3c;
use tock_registers::register_bitfields;
use tock_registers::LocalRegisterCopy;

pub const MDB_PENDING_READ_MCTP: u8 = 0xae;
pub const MAX_READ_WRITE_SIZE: usize = 250;

register_bitfields! {
    u32,
        I3CResponseDescriptor [
            ErrStatus OFFSET(28) NUMBITS(4) [
                Success = 0,
                CRCError = 1,
                ParityError = 2,
                FrameError = 3,
                AddrHeaderError = 4,
                Nack = 5,
                Overflow = 6,
                ShortReadError = 7,
                Aborted = 8,
                BusError = 9,
                NotSupported = 10,
                Reserved0 = 11,
                Reserved1 = 12,
                Reserved2 = 13,
                Reserved3 = 14,
                Reserved4 = 15,
            ],
            TID OFFSET(24) NUMBITS(4) [],
            DataLength OFFSET(0) NUMBITS(16) [],
        ],
    IbiDescriptor [
        ReceivedStatus OFFSET(31) NUMBITS(1) [],
        Error OFFSET(30) NUMBITS(1) [],
        StatusType OFFSET(27) NUMBITS(3) [
            Regular = 0,
            CreditAck = 1,
            ScheduledCmd = 2,
            AutocmdRead = 4,
            StbyCrBcastCcc = 7,
        ],
        TimestampPreset OFFSET(25) NUMBITS(1) [],
        LastStatus OFFSET(24) NUMBITS(1) [],
        Chunks OFFSET(16) NUMBITS(8) [],
        ID OFFSET(8) NUMBITS(8) [],
        DataLength OFFSET(0) NUMBITS(8) [],
    ]
}

register_bitfields! {
    u64,
    I3CCommandDescriptor [
        RNW OFFSET(29) NUMBITS(1) [
            Write = 0,
            Read = 1,
        ],
        DataLength OFFSET(48) NUMBITS(16) [],
    ],
}

pub struct I3CCore<'a, A: Alarm<'a>> {
    registers: StaticRef<I3c>,
    tx_client: OptionalCell<&'a dyn TxClient>,
    rx_client: OptionalCell<&'a dyn RxClient>,

    // buffers data to be received from the controller when it issues a write to us
    rx_buffer: TakeCell<'static, [u8]>,
    rx_buffer_idx: Cell<usize>,
    rx_buffer_size: Cell<usize>,

    // buffers data to be sent to the controller when it issues a read to us
    tx_buffer: TakeCell<'static, [u8]>,
    tx_buffer_idx: Cell<usize>,
    tx_buffer_size: Cell<usize>,

    // alarm conditions
    alarm: VirtualMuxAlarm<'a, A>,
    retry_outgoing_read: Cell<bool>,
    retry_incoming_write: Cell<bool>,
}

impl<'a, A: Alarm<'a>> I3CCore<'a, A> {
    // bit 4 = 0: we don't support virtual targets
    // bit 3 = 0: we will always respond to bus commands
    // bit 2 = 0: no ibi data bytes
    // bit 1 = 2: ibi request capable
    // bit 0 = 0: no max data speed limitation
    const BCR: u32 = 2;
    // how long to wait to retry
    const RETRY_WAIT_TICKS: u32 = 1000;

    pub fn new(base: StaticRef<I3c>, alarm: &'a MuxAlarm<'a, A>) -> Self {
        I3CCore {
            registers: base,
            tx_client: OptionalCell::empty(),
            rx_client: OptionalCell::empty(),
            rx_buffer: TakeCell::empty(),
            rx_buffer_idx: Cell::new(0),
            rx_buffer_size: Cell::new(0),
            tx_buffer: TakeCell::empty(),
            tx_buffer_idx: Cell::new(0),
            tx_buffer_size: Cell::new(0),
            alarm: VirtualMuxAlarm::new(alarm),
            retry_outgoing_read: Cell::new(false),
            retry_incoming_write: Cell::new(false),
        }
    }

    pub fn configure(&self, device_characteristic: u8) {
        self.registers.stdby_ctrl_mode_stby_cr_device_char.modify(
            StbyCrDeviceChar::Dcr.val(device_characteristic as u32)
                + StbyCrDeviceChar::BcrVar.val(Self::BCR),
        );
    }

    pub fn init(&'static self) {
        // Run the initialization steps for the primary and secondary controller from:
        // https://chipsalliance.github.io/i3c-core/initialization.html
        self.alarm.setup();
        self.alarm.set_alarm_client(self);

        // Verify the value of the HCI_VERSION register at the I3CBase address. The controller is compliant with MIPI HCI v1.2 and therefore the HCI_VERSION should read 0x120
        if self.registers.i3c_base_hci_version.get() != 0x120 {
            panic!("HCI version is not 0x120");
        }
        if !self
            .registers
            .stdby_ctrl_mode_stby_cr_capabilities
            .is_set(StbyCrCapabilities::TargetXactSupport)
        {
            panic!("I3C target transaction support is not enabled");
        }

        // Evaluate RING_HEADERS_SECTION_OFFSET, the SECTION_OFFSET should read 0x0 as this controller doesn’t support the DMA mode
        let rhso = self
            .registers
            .i3c_base_ring_headers_section_offset
            .read(RingHeadersSectionOffset::SectionOffset);
        if rhso != 0 {
            panic!("RING_HEADERS_SECTION_OFFSET is not 0");
        }

        // initialize timing registers
        self.registers.soc_mgmt_if_t_r_reg.set(0x2);
        self.registers.soc_mgmt_if_t_hd_dat_reg.set(0xa);
        self.registers.soc_mgmt_if_t_su_dat_reg.set(0xa);

        // Setup the threshold for the HCI queues (in the internal/private software data structures):
        self.registers.piocontrol_queue_thld_ctrl.modify(
            QueueThldCtrl::CmdEmptyBufThld.val(0)
                + QueueThldCtrl::RespBufThld.val(1)
                + QueueThldCtrl::IbiStatusThld.val(1),
        );

        self.registers.stdby_ctrl_mode_stby_cr_control.modify(
            StbyCrControl::StbyCrEnableInit::SET // enable the standby controller
                + StbyCrControl::TargetXactEnable::SET // enable Target Transaction Interface
                + StbyCrControl::DaaEntdaaEnable::SET // enable dynamic address assignment
                + StbyCrControl::BastCccIbiRing.val(0) // Set the IBI to use ring buffer 0
                + StbyCrControl::PrimeAcceptGetacccr::CLEAR // // don't auto-accept primary controller role
                + StbyCrControl::AcrFsmOpSelect::CLEAR, // don't become the active controller and set us as not the bus owner
        );

        // set TTI queue thresholds
        self.registers.tti_tti_queue_thld_ctrl.modify(
            TtiQueueThldCtrl::IbiThld.val(1)
                + TtiQueueThldCtrl::RxDescThld.val(1)
                + TtiQueueThldCtrl::TxDescThld.val(1),
        );

        // enable the PHY connection to the bus
        self.registers
            .i3c_base_hc_control
            .modify(ModeSelector::SET + BusEnable::CLEAR); // clear is enabled, set is suspended
    }

    pub fn enable_interrupts(&self) {
        self.registers.tti_interrupt_enable.modify(
            InterruptEnable::IbiThldStatEn::SET
                + InterruptEnable::RxDescThldStatEn::SET
                + InterruptEnable::TxDescThldStatEn::SET
                + InterruptEnable::RxDataThldStatEn::SET
                + InterruptEnable::TxDataThldStatEn::SET,
        );
    }

    pub fn disable_interrupts(&self) {
        self.registers.tti_interrupt_enable.modify(
            InterruptEnable::IbiThldStatEn::CLEAR
                + InterruptEnable::RxDescThldStatEn::CLEAR
                + InterruptEnable::TxDescThldStatEn::CLEAR
                + InterruptEnable::RxDataThldStatEn::CLEAR
                + InterruptEnable::TxDataThldStatEn::CLEAR,
        );
    }

    pub fn handle_interrupt(&self, _error: bool) {
        let tti_interrupts = self.registers.tti_interrupt_status.extract();
        if tti_interrupts.get() != 0 {
            // Bus error occurred
            if tti_interrupts.read(InterruptStatus::TransferErrStat) != 0 {
                self.transfer_error();
                // clear the interrupt
                self.registers
                    .tti_interrupt_status
                    .write(InterruptStatus::TransferErrStat::SET);
            }
            // Bus aborted transaction
            if tti_interrupts.read(InterruptStatus::TransferAbortStat) != 0 {
                self.transfer_error();
                // clear the interrupt
                self.registers
                    .tti_interrupt_status
                    .write(InterruptStatus::TransferAbortStat::SET);
            }
            // TTI IBI Buffer Threshold Status, the Target Controller shall set this bit to 1 when the number of available entries in the TTI IBI Queue is >= the value defined in `TTI_IBI_THLD`
            if tti_interrupts.read(InterruptStatus::IbiThldStat) != 0 {
                debug!("Ignoring I3C IBI threshold interrupt");
                self.registers
                    .tti_interrupt_enable
                    .modify(InterruptEnable::IbiThldStatEn::CLEAR);
            }
            // TTI RX Descriptor Buffer Threshold Status, the Target Controller shall set this bit to 1 when the number of available entries in the TTI RX Descriptor Queue is >= the value defined in `TTI_RX_DESC_THLD`
            if tti_interrupts.read(InterruptStatus::RxDescThldStat) != 0 {
                debug!("Ignoring I3C RX descriptor buffer threshold interrupt");
                self.registers
                    .tti_interrupt_enable
                    .modify(InterruptEnable::RxDescThldStatEn::CLEAR);
            }
            // TTI TX Descriptor Buffer Threshold Status, the Target Controller shall set this bit to 1 when the number of available entries in the TTI TX Descriptor Queue is >= the value defined in `TTI_TX_DESC_THLD`
            if tti_interrupts.read(InterruptStatus::TxDescThldStat) != 0 {
                debug!("Ignoring I3C TX descriptor buffer threshold interrupt");
                self.registers
                    .tti_interrupt_enable
                    .modify(InterruptEnable::TxDescThldStatEn::CLEAR);
            }
            // TTI RX Data Buffer Threshold Status, the Target Controller shall set this bit to 1 when the number of entries in the TTI RX Data Queue is >= the value defined in `TTI_RX_DATA_THLD`
            if tti_interrupts.read(InterruptStatus::RxDataThldStat) != 0 {
                debug!("Ignoring I3C RX data buffer buffer threshold interrupt");
                self.registers
                    .tti_interrupt_enable
                    .modify(InterruptEnable::RxDataThldStatEn::CLEAR);
            }
            // TTI TX Data Buffer Threshold Status, the Target Controller shall set this bit to 1 when the number of available entries in the TTI TX Data Queue is >= the value defined in TTI_TX_DATA_THLD
            if tti_interrupts.read(InterruptStatus::TxDataThldStat) != 0 {
                debug!("Ignoring I3C TX data buffer buffer threshold interrupt");
                self.registers
                    .tti_interrupt_enable
                    .modify(InterruptEnable::TxDataThldStatEn::CLEAR);
            }
            // Pending Write was NACK’ed because the `TX_DESC_STAT` event was not handled in time
            if tti_interrupts.read(InterruptStatus::TxDescTimeout) != 0 {
                self.pending_write_nack();
                // clear the interrupt
                self.registers
                    .tti_interrupt_status
                    .write(InterruptStatus::TxDescTimeout::SET);
            }
            // Pending Read was NACK’ed because the `RX_DESC_STAT` event was not handled in time
            if tti_interrupts.read(InterruptStatus::RxDescTimeout) != 0 {
                self.pending_read_nack();
                // clear the interrupt
                self.registers
                    .tti_interrupt_status
                    .write(InterruptStatus::TxDescTimeout::SET);
            }
            // There is a pending Read Transaction on the I3C Bus. Software should write data to the TX Descriptor Queue and the TX Data Queue
            if tti_interrupts.read(InterruptStatus::TxDescStat) != 0 {
                self.handle_outgoing_read();
            }
            // There is a pending Write Transaction. Software should read data from the RX Descriptor Queue and the RX Data Queue
            if tti_interrupts.read(InterruptStatus::RxDescStat) != 0 {
                self.handle_incoming_write();
            }
        }
    }

    fn set_alarm(&self, ticks: u32) {
        let now = self.alarm.now();
        self.alarm.set_alarm(now, ticks.into());
    }

    pub fn handle_error_interrupt(&self) {
        self.handle_interrupt(true);
    }

    pub fn handle_notification_interrupt(&self) {
        self.handle_interrupt(false);
    }

    // called when TTI has a private Write with data for us to grab
    pub fn handle_incoming_write(&self) {
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
            return;
        }

        let rx_buffer = self.rx_buffer.take().unwrap();
        let mut buf_idx = self.rx_buffer_idx.get();
        let buf_size = self.rx_buffer_size.get();
        let desc0 = self.registers.tti_rx_desc_queue_port.get();
        let desc1 = self.registers.tti_rx_desc_queue_port.get();
        let desc = LocalRegisterCopy::<u64, I3CCommandDescriptor::Register>::new(
            ((desc1 as u64) << 32) | (desc0 as u64),
        );
        let len = desc.read(I3CCommandDescriptor::DataLength) as usize;

        // read everything
        let mut full = false;
        for i in (0..len.next_multiple_of(4)).step_by(4) {
            let data = self.registers.tti_rx_data_port.get().to_le_bytes();
            for (j, data_j) in data.iter().enumerate() {
                if buf_idx >= buf_size {
                    full = true;
                    break;
                }
                if let Some(x) = rx_buffer.get_mut(buf_idx) {
                    *x = *data_j;
                } else {
                    // check if we ran out of space or if this is just the padding
                    if i + j < len {
                        full = true;
                    }
                }
                buf_idx += 1;
            }
        }

        if full {
            // TODO: we need a way to say that the buffer was not big enough
        }

        // reset
        self.rx_buffer_idx.set(0);
        self.rx_buffer_size.set(0);

        self.rx_client.map(|client| {
            client.receive_write(rx_buffer, len.min(buf_size));
        });
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
            // TODO: get the correct structure of this descriptor
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
        // we're done
        self.tx_client.map(|client| {
            client.send_done(buf, Ok(()));
        });
        // TODO: if no tx_client then we just drop the buffer?
    }

    fn transfer_error(&self) {
        if self.tx_buffer.is_some() {
            self.tx_client.map(|client| {
                client.send_done(self.tx_buffer.take().unwrap(), Err(ErrorCode::FAIL))
            });
        }
    }

    fn pending_read_nack(&self) {
        if self.tx_buffer.is_some() {
            self.tx_client.map(|client| {
                client.send_done(self.tx_buffer.take().unwrap(), Err(ErrorCode::CANCEL));
            });
        }
    }

    fn pending_write_nack(&self) {
        // TODO: we have no way to send this to the client
    }

    fn send_ibi(&self, mdb: u8) {
        // TODO: it is unclear if we need to set anything else in the descriptor
        self.registers
            .tti_tti_ibi_port
            .set(IbiDescriptor::DataLength.val(1).value);
        self.registers.tti_tti_ibi_port.set(mdb as u32);
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
        let len = rx_buf.len();
        self.rx_buffer.replace(rx_buf);
        self.rx_buffer_idx.replace(0);
        self.rx_buffer_size.replace(len);
    }

    fn transmit_read(
        &self,
        tx_buf: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if self.tx_buffer.is_some() {
            return Err((ErrorCode::BUSY, tx_buf));
        }
        self.tx_buffer.replace(tx_buf);
        self.tx_buffer_idx.set(0);
        self.tx_buffer_size.set(len);
        // TODO: check that this is for MCTP or something else
        self.send_ibi(MDB_PENDING_READ_MCTP);
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
            max_read_len: MAX_READ_WRITE_SIZE,
            max_write_len: MAX_READ_WRITE_SIZE,
        }
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for I3CCore<'a, A> {
    fn alarm(&self) {
        if self.retry_outgoing_read.get() {
            self.handle_outgoing_read();
        }
        if self.retry_incoming_write.get() {
            self.handle_notification_interrupt();
        }
    }
}
