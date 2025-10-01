// Licensed under the Apache-2.0 license

use std::cell::RefCell;
use std::rc::Rc;

use crate::McuMailbox0Internal;
use caliptra_emu_bus::{ActionHandle, Clock, Ram, ReadWriteRegister, Timer};
use caliptra_emu_cpu::Irq;
use emulator_consts::{RAM_ORG, RAM_SIZE};
use emulator_registers_generated::axicdma::AxicdmaPeripheral;
use registers_generated::axicdma::bits::{AxicdmaBytesToTransfer, AxicdmaControl, AxicdmaStatus};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

pub enum DmaCtrlIntType {
    Error = 1,
    Event = 2,
}
#[derive(Clone, Copy, PartialEq)]
pub enum AXIPeripheral {
    McuSram = 0,
    ExternalSram = 1,
    McuMboxSram0 = 2,
    McuMboxSram1 = 3,
}

#[derive(Clone, Copy)]
pub struct AxiAddr {
    pub lo: u32,
    pub hi: u32,
}

pub enum DmaOpError {
    ReadError = 0,
    WriteError = 1,
}

const MCU_SRAM_START_ADDR: u64 = RAM_ORG as u64;
const MCU_SRAM_END_ADDR: u64 = (RAM_ORG + RAM_SIZE) as u64;

const EXTERNAL_SRAM_START_ADDR: u64 = 0xB00C_0000;
const EXTERNAL_SRAM_END_ADDR: u64 = 0xB010_0000;

const MCU_MBOX0_SRAM_START_ADDR: u64 = 0xA840_0000;
const MCU_MBOX0_SRAM_END_ADDR: u64 = 0xA860_0000;

const MCU_MBOX1_SRAM_START_ADDR: u64 = 0xA880_0000;
const MCU_MBOX1_SRAM_END_ADDR: u64 = 0xA8A0_0000;

pub struct AxiCDMA {
    // Register emulation
    control: ReadWriteRegister<u32, AxicdmaControl::Register>, // 0x00
    status: ReadWriteRegister<u32, AxicdmaStatus::Register>,   // 0x04
    src_addr_lsb: ReadWriteRegister<u32>,                      // 0x18
    src_addr_msb: ReadWriteRegister<u32>,                      // 0x1C
    dst_addr_lsb: ReadWriteRegister<u32>,                      // 0x20
    dst_addr_msb: ReadWriteRegister<u32>,                      // 0x24
    btt: ReadWriteRegister<u32, AxicdmaBytesToTransfer::Register>, // 0x28

    mcu_sram: Option<Rc<RefCell<Ram>>>,
    external_sram: Option<Rc<RefCell<Ram>>>,
    mcu_mailbox0: Option<McuMailbox0Internal>,
    mcu_mailbox1: Option<McuMailbox0Internal>,

    // IRQ emulation
    event_irq: Irq,
    error_irq: Irq,
    timer: Timer,
    operation_start: Option<ActionHandle>,
}

impl AxiCDMA {
    pub const IO_START_DELAY: u64 = 200;

    pub fn new(
        clock: &Clock,
        error_irq: Irq,
        event_irq: Irq,
        external_sram: Option<Rc<RefCell<Ram>>>,
        mcu_mailbox0: Option<McuMailbox0Internal>,
        mcu_mailbox1: Option<McuMailbox0Internal>,
    ) -> Result<Self, std::io::Error> {
        let timer = Timer::new(clock);
        Ok(Self {
            control: ReadWriteRegister::new(0),
            status: ReadWriteRegister::new(0),
            src_addr_lsb: ReadWriteRegister::new(0),
            src_addr_msb: ReadWriteRegister::new(0),
            dst_addr_lsb: ReadWriteRegister::new(0),
            dst_addr_msb: ReadWriteRegister::new(0),
            btt: ReadWriteRegister::new(0),
            mcu_sram: None,
            external_sram,
            mcu_mailbox0,
            mcu_mailbox1,
            timer,
            event_irq,
            error_irq,
            operation_start: None,
        })
    }

    fn raise_interrupt(&mut self, interrupt_type: DmaCtrlIntType) {
        match interrupt_type {
            DmaCtrlIntType::Error => {
                // Check if interrupt is enabled before raising it
                if self.control.reg.is_set(AxicdmaControl::ErrIrqEn) {
                    self.status.reg.modify(AxicdmaStatus::IrqError::SET);
                    self.error_irq.set_level(true);
                    self.timer.schedule_poll_in(1);
                }
            }
            DmaCtrlIntType::Event => {
                // Check if interrupt is enabled before raising it
                if self.control.reg.is_set(AxicdmaControl::IocIrqEn) {
                    self.status.reg.modify(AxicdmaStatus::IrqIoc::SET);
                    self.event_irq.set_level(true);
                    self.timer.schedule_poll_in(10);
                }
            }
        }
    }

    fn clear_interrupt(&mut self, interrupt_type: DmaCtrlIntType) {
        match interrupt_type {
            DmaCtrlIntType::Error => {
                self.status.reg.modify(AxicdmaStatus::IrqError::CLEAR);
                self.error_irq.set_level(false);
            }
            DmaCtrlIntType::Event => {
                self.status.reg.modify(AxicdmaStatus::IrqIoc::CLEAR);
                self.event_irq.set_level(false);
            }
        }
    }

    fn handle_io_completion(&mut self, io_compl: Result<(), DmaOpError>) {
        match io_compl {
            Ok(_) => {
                self.status.reg.modify(AxicdmaStatus::Idle::SET);
                self.raise_interrupt(DmaCtrlIntType::Event);
            }
            Err(_) => {
                self.status.reg.modify(AxicdmaStatus::Idle::SET);
                self.raise_interrupt(DmaCtrlIntType::Error);
            }
        }
    }

    fn get_axi_peripheral_type(addr: AxiAddr) -> Option<AXIPeripheral> {
        let addr = ((addr.hi as u64) << 32) | (addr.lo as u64);

        if (MCU_SRAM_START_ADDR..MCU_SRAM_END_ADDR).contains(&addr) {
            return Some(AXIPeripheral::McuSram);
        }
        if (EXTERNAL_SRAM_START_ADDR..EXTERNAL_SRAM_END_ADDR).contains(&addr) {
            return Some(AXIPeripheral::ExternalSram);
        }
        if (MCU_MBOX0_SRAM_START_ADDR..MCU_MBOX0_SRAM_END_ADDR).contains(&addr) {
            return Some(AXIPeripheral::McuMboxSram0);
        }
        if (MCU_MBOX1_SRAM_START_ADDR..MCU_MBOX1_SRAM_END_ADDR).contains(&addr) {
            return Some(AXIPeripheral::McuMboxSram1);
        }
        None
    }

    fn get_axi_ram(&self, peripheral: AXIPeripheral) -> Option<Rc<RefCell<Ram>>> {
        match peripheral {
            AXIPeripheral::McuSram => self.mcu_sram.clone(),
            AXIPeripheral::ExternalSram => self.external_sram.clone(),
            _ => None,
        }
    }

    fn ram_address_to_offset(addr: AxiAddr) -> Option<u32> {
        let peripheral = Self::get_axi_peripheral_type(addr);
        peripheral?;
        let peripheral = peripheral.unwrap();
        match peripheral {
            AXIPeripheral::McuSram => Some(addr.lo - RAM_ORG),
            AXIPeripheral::ExternalSram => Some(addr.lo - EXTERNAL_SRAM_START_ADDR as u32),
            AXIPeripheral::McuMboxSram0 => Some(addr.lo - MCU_MBOX0_SRAM_START_ADDR as u32),
            AXIPeripheral::McuMboxSram1 => Some(addr.lo - MCU_MBOX1_SRAM_START_ADDR as u32),
        }
    }

    fn start(&mut self) -> Result<(), DmaOpError> {
        let xfer_size = self.btt.reg.get() as usize;
        let source_addr: AxiAddr = AxiAddr {
            lo: self.src_addr_lsb.reg.get(),
            hi: self.src_addr_msb.reg.get(),
        };
        let dest_addr: AxiAddr = AxiAddr {
            lo: self.dst_addr_lsb.reg.get(),
            hi: self.dst_addr_msb.reg.get(),
        };
        let source_ram = Self::get_axi_peripheral_type(source_addr);
        if source_ram.is_none() {
            return Err(DmaOpError::ReadError);
        }
        let dest_ram = Self::get_axi_peripheral_type(dest_addr);
        if dest_ram.is_none() {
            return Err(DmaOpError::WriteError);
        }

        let source_addr = Self::ram_address_to_offset(source_addr).unwrap() as usize;
        let dest_addr = Self::ram_address_to_offset(dest_addr).unwrap() as usize;

        if dest_ram == Some(AXIPeripheral::McuMboxSram0) {
            let source_ram = self.get_axi_ram(source_ram.unwrap()).unwrap();
            let source_ram = source_ram.borrow_mut();
            let source_data = &source_ram.data()[source_addr..source_addr + xfer_size];

            if let Some(mbox0) = &self.mcu_mailbox0 {
                for (index, chunk) in source_data.chunks(4).enumerate() {
                    let mut data = [0u8; 4];
                    data[..chunk.len()].copy_from_slice(chunk);
                    let value = u32::from_le_bytes(data);
                    let regs = &mbox0.regs;
                    regs.lock()
                        .unwrap()
                        .write_mcu_mbox0_csr_mbox_sram(value, index + dest_addr);
                }
                return Ok(());
            } else {
                return Err(DmaOpError::WriteError);
            }
        } else if dest_ram == Some(AXIPeripheral::McuMboxSram1) {
            let source_ram = self.get_axi_ram(source_ram.unwrap()).unwrap();
            let source_ram = source_ram.borrow_mut();
            let source_data = &source_ram.data()[source_addr..source_addr + xfer_size];

            if let Some(mbox1) = &self.mcu_mailbox1 {
                for (index, chunk) in source_data.chunks(4).enumerate() {
                    let mut data = [0u8; 4];
                    data[..chunk.len()].copy_from_slice(chunk);
                    let value = u32::from_le_bytes(data);
                    let regs = &mbox1.regs;
                    regs.lock()
                        .unwrap()
                        .write_mcu_mbox0_csr_mbox_sram(value, index + dest_addr.div_ceil(4));
                }
                return Ok(());
            } else {
                return Err(DmaOpError::WriteError);
            }
        }

        if source_ram == dest_ram {
            let ram = self.get_axi_ram(source_ram.unwrap()).unwrap();
            let mut ram = ram.borrow_mut();
            let source_data: Vec<u8> = ram.data()[source_addr..source_addr + xfer_size].to_vec();

            ram.data_mut()[dest_addr..dest_addr + xfer_size].copy_from_slice(&source_data);
        } else {
            let source_ram = self.get_axi_ram(source_ram.unwrap()).unwrap();
            let source_ram = source_ram.borrow_mut();
            let dest_ram = self.get_axi_ram(dest_ram.unwrap()).unwrap();
            let mut dest_ram = dest_ram.borrow_mut();

            let source_data = &source_ram.data()[source_addr..source_addr + xfer_size];

            dest_ram.data_mut()[dest_addr..dest_addr + xfer_size].copy_from_slice(source_data);
        }

        Ok(())
    }

    fn process_io(&mut self) {
        if !self.btt.reg.is_set(AxicdmaBytesToTransfer::Btt) {
            return;
        }

        if self.status.reg.is_set(AxicdmaStatus::Idle) {
            return;
        }

        let io_compl = self.start();
        self.handle_io_completion(io_compl);
    }
}

impl AxicdmaPeripheral for AxiCDMA {
    fn set_dma_ram(&mut self, ram: std::rc::Rc<std::cell::RefCell<caliptra_emu_bus::Ram>>) {
        self.mcu_sram = Some(ram);
    }

    fn poll(&mut self) {
        if self.timer.fired(&mut self.operation_start) {
            self.process_io();
        }
    }

    fn read_axicdma_control(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<u32, AxicdmaControl::Register> {
        caliptra_emu_bus::ReadWriteRegister::new(self.control.reg.get())
    }
    fn write_axicdma_control(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<u32, AxicdmaControl::Register>,
    ) {
        if self.status.reg.is_set(AxicdmaStatus::IrqError)
            && val.reg.is_set(AxicdmaControl::ErrIrqEn)
        {
            self.error_irq.set_level(true);
            self.timer.schedule_poll_in(1);
        }

        if self.status.reg.is_set(AxicdmaStatus::IrqIoc) && val.reg.is_set(AxicdmaControl::IocIrqEn)
        {
            self.event_irq.set_level(true);
            self.timer.schedule_poll_in(1);
        }

        if val.reg.is_set(AxicdmaControl::Reset) {
            self.control.reg.set(0);
            self.status.reg.set(0);
            self.status.reg.modify(AxicdmaStatus::Idle::SET);
            self.src_addr_lsb.reg.set(0);
            self.src_addr_msb.reg.set(0);
            self.dst_addr_lsb.reg.set(0);
            self.dst_addr_msb.reg.set(0);
            self.btt.reg.set(0);
            self.operation_start = None;
            self.error_irq.set_level(false);
            self.event_irq.set_level(false);
            return;
        }

        self.control.reg.set(val.reg.get());
    }
    fn read_axicdma_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<u32, AxicdmaStatus::Register> {
        caliptra_emu_bus::ReadWriteRegister::new(self.status.reg.get())
    }
    fn write_axicdma_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::axicdma::bits::AxicdmaStatus::Register,
        >,
    ) {
        if val.reg.is_set(AxicdmaStatus::IrqError) {
            self.clear_interrupt(DmaCtrlIntType::Error);
        }
        if val.reg.is_set(AxicdmaStatus::IrqIoc) {
            self.clear_interrupt(DmaCtrlIntType::Event);
        }
    }
    fn read_axicdma_src_addr(&mut self) -> caliptra_emu_types::RvData {
        self.src_addr_lsb.reg.get()
    }
    fn write_axicdma_src_addr(&mut self, val: caliptra_emu_types::RvData) {
        self.src_addr_lsb.reg.set(val);
    }
    fn read_axicdma_src_addr_msb(&mut self) -> caliptra_emu_types::RvData {
        self.src_addr_msb.reg.get()
    }
    fn write_axicdma_src_addr_msb(&mut self, val: caliptra_emu_types::RvData) {
        self.src_addr_msb.reg.set(val);
    }
    fn read_axicdma_dst_addr(&mut self) -> caliptra_emu_types::RvData {
        self.dst_addr_lsb.reg.get()
    }
    fn write_axicdma_dst_addr(&mut self, val: caliptra_emu_types::RvData) {
        self.dst_addr_lsb.reg.set(val);
    }
    fn read_axicdma_dst_addr_msb(&mut self) -> caliptra_emu_types::RvData {
        self.dst_addr_msb.reg.get()
    }
    fn write_axicdma_dst_addr_msb(&mut self, val: caliptra_emu_types::RvData) {
        self.dst_addr_msb.reg.set(val);
    }
    fn read_axicdma_bytes_to_transfer(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<u32, AxicdmaBytesToTransfer::Register> {
        caliptra_emu_bus::ReadWriteRegister::new(self.btt.reg.get())
    }
    fn write_axicdma_bytes_to_transfer(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<u32, AxicdmaBytesToTransfer::Register>,
    ) {
        self.btt.reg.set(val.reg.get());
        self.status.reg.modify(AxicdmaStatus::Idle::CLEAR);
        if self.btt.reg.is_set(AxicdmaBytesToTransfer::Btt) {
            // Schedule the timer to start the operation after the delay
            self.operation_start = Some(self.timer.schedule_poll_in(Self::IO_START_DELAY));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use caliptra_emu_bus::{Bus, Clock};
    use caliptra_emu_cpu::Pic;
    use caliptra_emu_types::RvSize;
    use emulator_consts::{EXTERNAL_TEST_SRAM_SIZE, RAM_SIZE};
    use emulator_registers_generated::root_bus::AutoRootBus;
    use registers_generated::axicdma::bits::{AxicdmaControl, AxicdmaStatus};
    use registers_generated::axicdma::AXICDMA_ADDR;

    const AXICDMA_CONTROL_OFFSET: u32 = 0x0;
    const AXICDMA_STATUS_OFFSET: u32 = 0x4;
    const AXICDMA_SRC_ADDR_OFFSET: u32 = 0x18;
    const AXICDMA_SRC_ADDR_MSB_OFFSET: u32 = 0x1C;
    const AXICDMA_DST_ADDR_OFFSET: u32 = 0x20;
    const AXICDMA_DST_ADDR_MSB_OFFSET: u32 = 0x24;
    const AXICDMA_BYTES_TO_TRANSFER_OFFSET: u32 = 0x28;

    // Dummy DMA RAM
    fn test_helper_setup_dummy_mcu_sram() -> Rc<RefCell<Ram>> {
        Rc::new(RefCell::new(Ram::new(vec![0u8; RAM_SIZE as usize])))
    }

    fn test_helper_setup_dummy_external_sram() -> Rc<RefCell<Ram>> {
        Rc::new(RefCell::new(Ram::new(vec![
            0u8;
            EXTERNAL_TEST_SRAM_SIZE as usize
        ])))
    }

    fn test_helper_setup_autobus(
        clock: &Clock,
        mcu_sram: Option<Rc<RefCell<Ram>>>,
        external_sram: Option<Rc<RefCell<Ram>>>,
    ) -> AutoRootBus {
        let pic = Pic::new();
        let (dma_ctrl_error_irq, dma_ctrl_event_irq) = (pic.register_irq(23), pic.register_irq(24));

        let mut dma_controller = Box::new(
            AxiCDMA::new(
                clock,
                dma_ctrl_error_irq,
                dma_ctrl_event_irq,
                external_sram,
                None,
                None,
            )
            .unwrap(),
        );

        if let Some(mcu_sram) = mcu_sram {
            AxiCDMA::set_dma_ram(&mut *dma_controller, mcu_sram);
        }

        AutoRootBus::new(
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(dma_controller),
        )
    }

    #[test]
    fn test_main_dma_regs_access() {
        let dummy_clock = Clock::new();
        let mut bus = test_helper_setup_autobus(&dummy_clock, None, None);

        let dma_ctrl_base_addr: u32 = AXICDMA_ADDR;

        // Write to the control register and read it back
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + AXICDMA_CONTROL_OFFSET,
            AxicdmaControl::IocIrqEn::SET.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + AXICDMA_CONTROL_OFFSET)
                .unwrap(),
            AxicdmaControl::IocIrqEn::SET.value
        );

        // Clear the control register and read it back
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + AXICDMA_CONTROL_OFFSET,
            AxicdmaControl::IocIrqEn::CLEAR.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + AXICDMA_CONTROL_OFFSET)
                .unwrap(),
            AxicdmaControl::IocIrqEn::CLEAR.value
        );
    }

    #[test]
    fn test_main_dma_mcu_to_external_sram() {
        let dummy_clock = Clock::new();
        let dummy_mcu_sram = test_helper_setup_dummy_mcu_sram();
        let dummy_external_sram = test_helper_setup_dummy_external_sram();
        let mut bus = test_helper_setup_autobus(
            &dummy_clock,
            Some(dummy_mcu_sram.clone()),
            Some(dummy_external_sram.clone()),
        );

        let dma_ctrl_base_addr: u32 = AXICDMA_ADDR;

        // Fill mcu_sram with test data
        let test_data = [0x55u8; 0x1000];
        dummy_mcu_sram.borrow_mut().data_mut()[0..0x1000].copy_from_slice(&test_data);

        // Setup the source and destination addresses
        let source_axi_addr = AxiAddr {
            lo: RAM_ORG,
            hi: 0x0000_0000,
        };
        let dest_axi_addr = AxiAddr {
            lo: EXTERNAL_SRAM_START_ADDR as u32,
            hi: 0x0000_0000,
        };
        let xfer_size = 0x1000;

        // Reset the DMA controller
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + AXICDMA_CONTROL_OFFSET,
            AxicdmaControl::Reset::SET.value,
        )
        .unwrap();

        // Enable the interrupt
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr,
            AxicdmaControl::IocIrqEn::SET.value,
        )
        .unwrap();

        // Write to the source address registers
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + AXICDMA_SRC_ADDR_OFFSET,
            source_axi_addr.lo,
        )
        .unwrap();
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + AXICDMA_SRC_ADDR_MSB_OFFSET,
            source_axi_addr.hi,
        )
        .unwrap();

        // Write to the destination address registers
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + AXICDMA_DST_ADDR_OFFSET,
            dest_axi_addr.lo,
        )
        .unwrap();
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + AXICDMA_DST_ADDR_MSB_OFFSET,
            dest_axi_addr.hi,
        )
        .unwrap();

        // Write to the transfer size register and start the transfer
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + AXICDMA_BYTES_TO_TRANSFER_OFFSET,
            xfer_size as u32,
        )
        .unwrap();

        // Wait for the transfer to complete
        for _ in 0..1000 {
            dummy_clock.increment_and_process_timer_actions(1, &mut bus);
        }
        bus.poll();

        // Check the status register
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + AXICDMA_STATUS_OFFSET)
                .unwrap(),
            AxicdmaStatus::IrqIoc::SET.value + AxicdmaStatus::Idle::SET.value
        );

        // Verify the data in the external sram
        let start_offset = (((dest_axi_addr.hi as u64) << 32)
            | (dest_axi_addr.lo as u64 - EXTERNAL_SRAM_START_ADDR))
            as usize;
        let dest_data = dummy_external_sram.borrow_mut().data_mut()
            [start_offset..start_offset + xfer_size]
            .to_vec();
        assert_eq!(dest_data, test_data);

        // Clear the interrupt
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + AXICDMA_STATUS_OFFSET,
            AxicdmaStatus::IrqIoc::SET.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + AXICDMA_STATUS_OFFSET)
                .unwrap(),
            AxicdmaStatus::Idle::SET.value
        );
    }
}
