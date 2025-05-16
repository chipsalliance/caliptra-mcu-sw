/*++

Licensed under the Apache-2.0 license.

File Name:

    dma_ctrl.rs

Abstract:

    File contains dummy dma controller peripheral emulation.

--*/

use emulator_bus::{ActionHandle, Clock, Ram, ReadWriteRegister, Timer};
use emulator_consts::RAM_OFFSET;
use emulator_cpu::Irq;
use emulator_registers_generated::dma::DmaPeripheral;
use registers_generated::dma_ctrl::bits::*;
use std::cell::RefCell;
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

pub enum DmaCtrlIntType {
    Error = 1,
    Event = 2,
}
#[derive(Clone, Copy, PartialEq)]
pub enum AXIPeripheral {
    McuSram = 0,
    ExternalSram = 1,
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

const MCU_SRAM_END_ADDR: AxiAddr = AxiAddr {
    lo: 0xffff_ffff,
    hi: 0x1000_0000,
};

const EXTERNAL_SRAM_END_ADDR: AxiAddr = AxiAddr {
    lo: 0xffff_ffff,
    hi: 0x2000_0000,
};

/// A dummy dma controller peripheral for emulation purposes.
pub struct DummyDmaCtrl {
    interrupt_state: ReadWriteRegister<u32, DmaInterruptState::Register>,
    interrupt_enable: ReadWriteRegister<u32, DmaInterruptEnable::Register>,
    xfer_size: ReadWriteRegister<u32>,
    source_addr_high: ReadWriteRegister<u32>,
    source_addr_low: ReadWriteRegister<u32>,
    dest_addr_high: ReadWriteRegister<u32>,
    dest_addr_low: ReadWriteRegister<u32>,
    control: ReadWriteRegister<u32, DmaControl::Register>,
    op_status: ReadWriteRegister<u32, DmaOpStatus::Register>,
    mcu_sram: Option<Rc<RefCell<Ram>>>,
    external_sram: Option<Rc<RefCell<Ram>>>,
    timer: Timer,
    operation_start: Option<ActionHandle>,
    error_irq: Irq,
    event_irq: Irq,
}

impl DummyDmaCtrl {
    pub const IO_START_DELAY: u64 = 200;

    pub fn new(
        clock: &Clock,
        error_irq: Irq,
        event_irq: Irq,
        external_sram: Option<Rc<RefCell<Ram>>>,
    ) -> Result<Self, std::io::Error> {
        let timer = Timer::new(clock);

        Ok(Self {
            mcu_sram: None,
            external_sram,
            interrupt_state: ReadWriteRegister::new(0x0000_0000),
            interrupt_enable: ReadWriteRegister::new(0x0000_0000),

            xfer_size: ReadWriteRegister::new(0x0000_0000),
            source_addr_high: ReadWriteRegister::new(0x0000_0000),
            source_addr_low: ReadWriteRegister::new(0x0000_0000),
            dest_addr_high: ReadWriteRegister::new(0x0000_0000),
            dest_addr_low: ReadWriteRegister::new(0x0000_0000),
            control: ReadWriteRegister::new(0x0000_0000),
            op_status: ReadWriteRegister::new(0x0000_0000),

            timer,
            operation_start: None,
            error_irq,
            event_irq,
        })
    }

    fn raise_interrupt(&mut self, interrupt_type: DmaCtrlIntType) {
        match interrupt_type {
            DmaCtrlIntType::Error => {
                self.interrupt_state
                    .reg
                    .modify(DmaInterruptState::Error::SET);
                // Check if interrupt is enabled before raising it
                if self.interrupt_enable.reg.is_set(DmaInterruptEnable::Error) {
                    self.error_irq.set_level(true);
                    self.timer.schedule_poll_in(1);
                }
            }
            DmaCtrlIntType::Event => {
                self.interrupt_state
                    .reg
                    .modify(DmaInterruptState::Event::SET);
                // Check if interrupt is enabled before raising it
                if self.interrupt_enable.reg.is_set(DmaInterruptEnable::Event) {
                    self.event_irq.set_level(true);
                    self.timer.schedule_poll_in(10);
                }
            }
        }
    }

    fn clear_interrupt(&mut self, interrupt_type: DmaCtrlIntType) {
        match interrupt_type {
            DmaCtrlIntType::Error => {
                self.interrupt_state
                    .reg
                    .modify(DmaInterruptState::Error::CLEAR);
                self.error_irq.set_level(false);
            }
            DmaCtrlIntType::Event => {
                self.interrupt_state
                    .reg
                    .modify(DmaInterruptState::Event::CLEAR);
                self.event_irq.set_level(false);
            }
        }
    }

    fn handle_io_completion(&mut self, io_compl: Result<(), DmaOpError>) {
        match io_compl {
            Ok(_) => {
                self.op_status.reg.modify(DmaOpStatus::Done::SET);
                self.raise_interrupt(DmaCtrlIntType::Event);
            }
            Err(error_type) => {
                self.op_status
                    .reg
                    .modify(DmaOpStatus::Err.val(error_type as u32));
                self.raise_interrupt(DmaCtrlIntType::Error);
            }
        }
    }

    fn get_axi_peripheral_type(addr: AxiAddr) -> Option<AXIPeripheral> {
        match addr {
            AxiAddr { hi, .. } if hi <= MCU_SRAM_END_ADDR.hi => Some(AXIPeripheral::McuSram),
            AxiAddr { hi, .. } if hi <= EXTERNAL_SRAM_END_ADDR.hi => {
                Some(AXIPeripheral::ExternalSram)
            }
            _ => None,
        }
    }

    fn get_axi_ram(&self, peripeheral: AXIPeripheral) -> Option<Rc<RefCell<Ram>>> {
        match peripeheral {
            AXIPeripheral::McuSram => self.mcu_sram.clone(),
            AXIPeripheral::ExternalSram => self.external_sram.clone(),
        }
    }

    fn ram_address_to_offset(addr: AxiAddr) -> Option<u32> {
        let peripheral = Self::get_axi_peripheral_type(addr);
        peripheral?;
        let peripheral = peripheral.unwrap();
        match peripheral {
            AXIPeripheral::McuSram => Some(addr.lo - RAM_OFFSET),
            AXIPeripheral::ExternalSram => Some(addr.lo),
        }
    }

    fn start(&mut self) -> Result<(), DmaOpError> {
        let xfer_size = self.xfer_size.reg.get() as usize;
        let source_addr: AxiAddr = AxiAddr {
            lo: self.source_addr_low.reg.get(),
            hi: self.source_addr_high.reg.get(),
        };
        let dest_addr: AxiAddr = AxiAddr {
            lo: self.dest_addr_low.reg.get(),
            hi: self.dest_addr_high.reg.get(),
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
        if !self.control.reg.is_set(DmaControl::Start) {
            return;
        }

        if self.op_status.reg.is_set(DmaOpStatus::Done) {
            return;
        }

        let io_compl = self.start();
        self.handle_io_completion(io_compl);
    }
}

impl DmaPeripheral for DummyDmaCtrl {
    fn set_dma_ram(&mut self, ram: std::rc::Rc<std::cell::RefCell<emulator_bus::Ram>>) {
        self.mcu_sram = Some(ram);
    }

    fn poll(&mut self) {
        if self.timer.fired(&mut self.operation_start) {
            self.process_io();
        }
    }

    fn read_dma_interrupt_state(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::dma_ctrl::bits::DmaInterruptState::Register,
    > {
        emulator_bus::ReadWriteRegister::new(self.interrupt_state.reg.get())
    }

    fn write_dma_interrupt_state(
        &mut self,
        val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::dma_ctrl::bits::DmaInterruptState::Register,
        >,
    ) {
        // Interrupt state register: SW write 1 to clear
        if val
            .reg
            .is_set(registers_generated::dma_ctrl::bits::DmaInterruptState::Error)
        {
            self.clear_interrupt(DmaCtrlIntType::Error);
        }
        if val
            .reg
            .is_set(registers_generated::dma_ctrl::bits::DmaInterruptState::Event)
        {
            self.clear_interrupt(DmaCtrlIntType::Event);
        }
    }

    fn read_dma_interrupt_enable(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::dma_ctrl::bits::DmaInterruptEnable::Register,
    > {
        emulator_bus::ReadWriteRegister::new(self.interrupt_enable.reg.get())
    }

    fn write_dma_interrupt_enable(
        &mut self,
        val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::dma_ctrl::bits::DmaInterruptEnable::Register,
        >,
    ) {
        if self.interrupt_state.reg.is_set(DmaInterruptState::Error)
            && val
                .reg
                .is_set(registers_generated::dma_ctrl::bits::DmaInterruptEnable::Error)
        {
            self.error_irq.set_level(true);
            self.timer.schedule_poll_in(1);
        }

        if self.interrupt_state.reg.is_set(DmaInterruptState::Event)
            && val
                .reg
                .is_set(registers_generated::dma_ctrl::bits::DmaInterruptEnable::Event)
        {
            self.event_irq.set_level(true);
            self.timer.schedule_poll_in(1);
        }

        self.interrupt_enable.reg.set(val.reg.get());
    }

    fn read_xfer_size(&mut self) -> caliptra_emu_types::RvData {
        self.xfer_size.reg.get()
    }

    fn write_xfer_size(&mut self, val: caliptra_emu_types::RvData) {
        self.xfer_size.reg.set(val);
    }

    fn read_source_addr_high(&mut self) -> caliptra_emu_types::RvData {
        self.source_addr_high.reg.get()
    }

    fn write_source_addr_high(&mut self, _val: caliptra_emu_types::RvData) {
        self.source_addr_high.reg.set(_val);
    }

    fn read_source_addr_lower(&mut self) -> caliptra_emu_types::RvData {
        self.source_addr_low.reg.get()
    }
    fn write_source_addr_lower(&mut self, _val: caliptra_emu_types::RvData) {
        self.source_addr_low.reg.set(_val);
    }

    fn read_dest_addr_high(&mut self) -> caliptra_emu_types::RvData {
        self.dest_addr_high.reg.get()
    }
    fn write_dest_addr_high(&mut self, val: caliptra_emu_types::RvData) {
        self.dest_addr_high.reg.set(val);
    }
    fn read_dest_addr_lower(&mut self) -> caliptra_emu_types::RvData {
        self.dest_addr_low.reg.get()
    }
    fn write_dest_addr_lower(&mut self, val: caliptra_emu_types::RvData) {
        self.dest_addr_low.reg.set(val);
    }
    fn read_dma_control(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::dma_ctrl::bits::DmaControl::Register,
    > {
        emulator_bus::ReadWriteRegister::new(self.control.reg.get())
    }
    fn write_dma_control(
        &mut self,
        val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::dma_ctrl::bits::DmaControl::Register,
        >,
    ) {
        // Set the control register with the new value
        self.control.reg.set(val.reg.get());

        if self.control.reg.is_set(DmaControl::Start) {
            // Schedule the timer to start the operation after the delay
            self.operation_start = Some(self.timer.schedule_poll_in(Self::IO_START_DELAY));
        }
    }
    fn read_dma_op_status(
        &mut self,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::dma_ctrl::bits::DmaOpStatus::Register,
    > {
        emulator_bus::ReadWriteRegister::new(self.op_status.reg.get())
    }
    fn write_dma_op_status(
        &mut self,
        val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::dma_ctrl::bits::DmaOpStatus::Register,
        >,
    ) {
        self.op_status.reg.set(val.reg.get());
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use caliptra_emu_types::RvSize;
    use emulator_bus::{Bus, Clock};
    use emulator_consts::{EXTERNAL_TEST_SRAM_SIZE, RAM_SIZE};
    use emulator_cpu::Pic;
    use emulator_registers_generated::root_bus::AutoRootBus;
    use registers_generated::dma_ctrl::bits::{
        DmaControl, DmaInterruptEnable, DmaInterruptState, DmaOpStatus,
    };
    use registers_generated::dma_ctrl::DMA_CTRL_ADDR;

    pub const DMA_INTERRUPT_STATE_OFFSET: u32 = 0x00;
    pub const DMA_INTERRUPT_ENABLE_OFFSET: u32 = 0x04;
    pub const XFER_SIZE_OFFSET: u32 = 0x08;
    pub const SOURCE_ADDR_HIGH_OFFSET: u32 = 0x0C;
    pub const SOURCE_ADDR_LOWER_OFFSET: u32 = 0x10;
    pub const DEST_ADDR_HIGH_OFFSET: u32 = 0x14;
    pub const DEST_ADDR_LOWER_OFFSET: u32 = 0x18;
    pub const DMA_CONTROL_OFFSET: u32 = 0x1C;
    pub const DMA_OP_STATUS_OFFSET: u32 = 0x20;
    const MCU_SRAM_HI_OFFSET: u32 = 0x1000_0000;
    const EXTERNAL_SRAM_HI_OFFSET: u32 = 0x2000_0000;

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
            DummyDmaCtrl::new(clock, dma_ctrl_error_irq, dma_ctrl_event_irq, external_sram)
                .unwrap(),
        );

        if let Some(mcu_sram) = mcu_sram {
            DmaPeripheral::set_dma_ram(&mut *dma_controller, mcu_sram);
        }

        AutoRootBus::new(
            vec![],
            None,
            None,
            None,
            None,
            None,
            Some(dma_controller),
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    fn test_dma_ctrl_regs_access() {
        let dummy_clock = Clock::new();
        // Create a auto root bus
        let mut bus = test_helper_setup_autobus(&dummy_clock, None, None);

        let dma_ctrl_base_addr: u32 = DMA_CTRL_ADDR;

        // Write to the interrupt enable register and read it back
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + DMA_INTERRUPT_ENABLE_OFFSET,
            DmaInterruptEnable::Error::SET.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(
                RvSize::Word,
                dma_ctrl_base_addr + DMA_INTERRUPT_ENABLE_OFFSET
            )
            .unwrap(),
            DmaInterruptEnable::Error::SET.value
        );

        // Clear the interrupt enable register and read it back
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + DMA_INTERRUPT_ENABLE_OFFSET,
            DmaInterruptEnable::Error::CLEAR.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(
                RvSize::Word,
                dma_ctrl_base_addr + DMA_INTERRUPT_ENABLE_OFFSET
            )
            .unwrap(),
            DmaInterruptEnable::Error::CLEAR.value
        );

        // Write to the interrupt state register and read it back
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + DMA_INTERRUPT_STATE_OFFSET,
            DmaInterruptState::Error::SET.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(
                RvSize::Word,
                dma_ctrl_base_addr + DMA_INTERRUPT_STATE_OFFSET
            )
            .unwrap(),
            DmaInterruptState::Error::CLEAR.value
        );

        // Write to the XFER_SIZE_OFFSET and read it back
        bus.write(RvSize::Word, dma_ctrl_base_addr + XFER_SIZE_OFFSET, 0x1000)
            .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + XFER_SIZE_OFFSET)
                .unwrap(),
            0x1000
        );

        // Write to the source address high register and read it back
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + SOURCE_ADDR_HIGH_OFFSET,
            0x2000,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + SOURCE_ADDR_HIGH_OFFSET)
                .unwrap(),
            0x2000
        );
        // Write to the source address low register and read it back
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + SOURCE_ADDR_LOWER_OFFSET,
            0x3000,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + SOURCE_ADDR_LOWER_OFFSET)
                .unwrap(),
            0x3000
        );
        // Write to the destination address high register and read it back
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + DEST_ADDR_HIGH_OFFSET,
            0x4000,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + DEST_ADDR_HIGH_OFFSET)
                .unwrap(),
            0x4000
        );
        // Write to the destination address low register and read it back
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + DEST_ADDR_LOWER_OFFSET,
            0x5000,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + DEST_ADDR_LOWER_OFFSET)
                .unwrap(),
            0x5000
        );
        // Write to the control register and read it back
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + DMA_CONTROL_OFFSET,
            DmaControl::Start::SET.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + DMA_CONTROL_OFFSET)
                .unwrap(),
            DmaControl::Start::SET.value
        );
    }

    fn test_dma_mcu_to_external_sram() {
        let dummy_clock = Clock::new();
        let dummy_mcu_sram = test_helper_setup_dummy_mcu_sram();
        let dummy_external_sram = test_helper_setup_dummy_external_sram();
        // Create a auto root bus
        let mut bus = test_helper_setup_autobus(
            &dummy_clock,
            Some(dummy_mcu_sram.clone()),
            Some(dummy_external_sram.clone()),
        );

        let dma_ctrl_base_addr: u32 = DMA_CTRL_ADDR;

        // Fill mcu_sram with test data
        let test_data = [0x55u8; 0x1000];
        dummy_mcu_sram.borrow_mut().data_mut()[0..0x1000].copy_from_slice(&test_data);

        // Setup the source and destination addresses
        let source_axi_addr = AxiAddr {
            lo: RAM_OFFSET,
            hi: MCU_SRAM_HI_OFFSET,
        };
        let dest_axi_addr = AxiAddr {
            lo: 0x0000_0000,
            hi: EXTERNAL_SRAM_HI_OFFSET,
        };
        let xfer_size = 0x1000;

        // Write to the source address high register
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + SOURCE_ADDR_HIGH_OFFSET,
            source_axi_addr.hi,
        )
        .unwrap();

        // Write to the source address low register
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + SOURCE_ADDR_LOWER_OFFSET,
            source_axi_addr.lo,
        )
        .unwrap();
        // Write to the destination address high register
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + DEST_ADDR_HIGH_OFFSET,
            dest_axi_addr.hi,
        )
        .unwrap();
        // Write to the destination address low register
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + DEST_ADDR_LOWER_OFFSET,
            dest_axi_addr.lo,
        )
        .unwrap();
        // Write to the transfer size register
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + XFER_SIZE_OFFSET,
            xfer_size as u32,
        )
        .unwrap();

        // Enable the interrupt
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + DMA_INTERRUPT_ENABLE_OFFSET,
            DmaInterruptEnable::Event::SET.value,
        )
        .unwrap();

        // Write to the control register to start the transfer
        bus.write(
            RvSize::Word,
            dma_ctrl_base_addr + DMA_CONTROL_OFFSET,
            DmaControl::Start::SET.value,
        )
        .unwrap();
        // Wait for the transfer to complete
        for _ in 0..1000 {
            dummy_clock.increment_and_process_timer_actions(1, &mut bus);
        }
        bus.poll();
        // Check the op_status register
        assert_eq!(
            bus.read(RvSize::Word, dma_ctrl_base_addr + DMA_OP_STATUS_OFFSET)
                .unwrap(),
            DmaOpStatus::Done::SET.value
        );
        // Check the interrupt state register
        assert_eq!(
            bus.read(
                RvSize::Word,
                dma_ctrl_base_addr + DMA_INTERRUPT_STATE_OFFSET
            )
            .unwrap(),
            DmaInterruptState::Event::SET.value
        );
        // Check the data in the external sram
        let start_offset = dest_axi_addr.lo as usize;
        let dest_data = dummy_external_sram.borrow_mut().data_mut()
            [start_offset..start_offset + xfer_size]
            .to_vec();
        // Verify the data in the external sram
        assert_eq!(dest_data, test_data);
    }

    /// TEST CASE STARTED HERE
    #[test]
    fn test_main_dma_regs_access() {
        test_dma_ctrl_regs_access();
    }

    #[test]
    fn test_main_dma_mcu_to_external_sram() {
        test_dma_mcu_to_external_sram();
    }
}
