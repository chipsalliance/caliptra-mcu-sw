/*++

Licensed under the Apache-2.0 license.

File Name:

    flash_ctrl.rs

Abstract:

    File contains dummy flash controller peripheral emulation.

--*/

use core::convert::TryInto;
use emulator_bus::{Clock, ReadOnlyRegister, ReadWriteRegister, Timer};
use emulator_cpu::Irq;
use emulator_derive::Bus;
use emulator_registers_generated::flash::FlashPeripheral;
use registers_generated::flash_ctrl::bits::{
    Control, CtrlRegwen, InterruptEnable, InterruptState, OpStatus,
};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

#[derive(Debug, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum FlashOperation {
    ReadPage = 1,
    WritePage = 2,
    ErasePage = 3,
}

impl TryInto<FlashOperation> for u32 {
    type Error = ();

    fn try_into(self) -> Result<FlashOperation, Self::Error> {
        match self {
            1 => Ok(FlashOperation::ReadPage),
            2 => Ok(FlashOperation::WritePage),
            3 => Ok(FlashOperation::ErasePage),
            _ => Err(()),
        }
    }
}

pub enum FlashCtrlIntType {
    Error = 1,
    Event = 2,
}

pub enum FlashOpError {
    ReadError = 0,
    WriteError = 1,
    EraseError = 2,
    InvalidOp = 3,
}

// Define a struct to represent the flash controller peripheral emulation.
// Includes IRQs, timers, and peripheral registers, backend storage and a buffer page_size for the flash controller.
#[derive(Bus)]
pub struct DummyFlashCtrl {
    #[register(offset = 0x00)]
    interrupt_state: ReadWriteRegister<u32, InterruptState::Register>,

    #[register(offset = 0x04)]
    interrupt_enable: ReadWriteRegister<u32, InterruptEnable::Register>,

    #[register(offset = 0x08)]
    page_size: ReadWriteRegister<u32>,

    #[register(offset = 0x0c)]
    page_num: ReadWriteRegister<u32>,

    #[register(offset = 0x10)]
    page_addr: ReadWriteRegister<u32>,

    #[register(offset = 0x14)]
    control: ReadWriteRegister<u32, Control::Register>,

    #[register(offset = 0x18)]
    op_status: ReadWriteRegister<u32, OpStatus::Register>,

    #[register(offset = 0x1c)]
    ctrl_regwen: ReadOnlyRegister<u32, CtrlRegwen::Register>,

    /// Timer
    timer: Timer,

    /// Backend flash storage file
    file: Option<File>,

    /// Internal buffer for read, write operations
    buffer: Vec<u8>,

    /// Operation pending flag
    operation_pending: bool,

    /// Error interrupt
    _error_irq: Irq,

    /// Event interrupt
    _event_irq: Irq,
}

impl DummyFlashCtrl {
    /// Page size for the flash storage connected to the controller.
    pub const PAGE_SIZE: usize = 1024;

    /// Maximum number of pages in the flash storage connected to the controller.
    /// This is a dummy value, the actual value should be set based on the flash storage size.
    pub const MAX_PAGES: u32 = 64 * 1024;

    pub fn new(
        clock: &Clock,
        file_name: Option<PathBuf>,
        error_irq: Irq,
        event_irq: Irq,
    ) -> Result<Self, std::io::Error> {
        let timer = Timer::new(clock);
        let file = if let Some(path) = file_name {
            Some(
                std::fs::File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path)?,
            )
        } else {
            None
        };

        Ok(Self {
            interrupt_state: ReadWriteRegister::new(0x0000_0000),
            interrupt_enable: ReadWriteRegister::new(0x0000_0000),
            page_size: ReadWriteRegister::new(0x0000_0000),
            page_num: ReadWriteRegister::new(0x0000_0000),
            page_addr: ReadWriteRegister::new(0x0000_0000),
            control: ReadWriteRegister::new(0x0000_0000),
            op_status: ReadWriteRegister::new(0x0000_0000),
            ctrl_regwen: ReadOnlyRegister::new(CtrlRegwen::En::SET.value),
            timer,
            file,
            buffer: vec![0; Self::PAGE_SIZE],
            operation_pending: false,
            _error_irq: error_irq,
            _event_irq: event_irq,
        })
    }

    fn raise_interrupt(&mut self, interrupt_type: FlashCtrlIntType) {
        match interrupt_type {
            FlashCtrlIntType::Error => {
                self.interrupt_state.reg.modify(InterruptState::Error::SET);
                self._error_irq.set_level(true);
                self.timer.schedule_poll_in(1);
            }
            FlashCtrlIntType::Event => {
                self.interrupt_state.reg.modify(InterruptState::Event::SET);
                self._event_irq.set_level(true);
                self.timer.schedule_poll_in(1);
            }
        }
    }

    fn handle_io_completion(&mut self, io_compl: Result<(), FlashOpError>) {
        match io_compl {
            Ok(_) => {
                self.op_status.reg.modify(OpStatus::Done::SET);
                self.raise_interrupt(FlashCtrlIntType::Event);
            }
            Err(error_type) => {
                self.op_status
                    .reg
                    .modify(OpStatus::Err.val(error_type as u32));
                self.raise_interrupt(FlashCtrlIntType::Error);
            }
        }
    }

    fn read_page(&mut self) -> Result<(), FlashOpError> {
        // Get the page number from the register
        let page_num = self.page_num.reg.get();

        // Sanity check for the page number, page size and file
        if page_num >= Self::MAX_PAGES
            || self.page_size.reg.get() < Self::PAGE_SIZE as u32
            || self.file.is_none()
        {
            print!("Read page failed sanity check");
            return Err(FlashOpError::ReadError);
        }

        // Read the entire page from the backend file and put into the internal buffer
        if let Some(file) = &mut self.file {
            let offset = (page_num * Self::PAGE_SIZE as u32) as u64;
            // Error handling for seek and read operations
            if file.seek(std::io::SeekFrom::Start(offset)).is_err()
                || file.read_exact(&mut self.buffer).is_err()
            {
                print!("Read page failed: seek or read error");
                return Err(FlashOpError::ReadError);
            }
        }

        // Copy the data from the internal buffer to the 'PAGE_ADDR' buffer that  will be used by the SW.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.buffer.as_ptr(),
                (self.page_addr.reg.get() as usize) as *mut u8,
                Self::PAGE_SIZE,
            );
        }

        Ok(())
    }

    fn write_page(&mut self) -> Result<(), FlashOpError> {
        // Get the page number from the register
        let page_num = self.page_num.reg.get();

        // Sanity check for the page number, page size and file
        if page_num >= Self::MAX_PAGES
            || self.page_size.reg.get() < Self::PAGE_SIZE as u32
            || self.file.is_none()
        {
            println!("Write page failed sanity check");
            return Err(FlashOpError::WriteError);
        }

        // Copy the data from the 'PAGE_ADDR' buffer to the internal buffer
        unsafe {
            std::ptr::copy_nonoverlapping(
                (self.page_addr.reg.get() as usize) as *const u8,
                self.buffer.as_mut_ptr(),
                Self::PAGE_SIZE,
            );
        }

        // Write the entire page from the buffer to the backend file
        if let Some(file) = &mut self.file {
            let offset = (page_num * Self::PAGE_SIZE as u32) as u64;
            // Error handling for seek and write operations
            if file.seek(std::io::SeekFrom::Start(offset)).is_err()
                || file.write_all(&self.buffer).is_err()
            {
                println!("Write page failed: seek or write error");
                return Err(FlashOpError::WriteError);
            }
        }

        Ok(())
    }

    fn erase_page(&mut self) -> Result<(), FlashOpError> {
        // Get the page number from the register
        let page_num = self.page_num.reg.get();

        // Sanity check for the page number and file
        if page_num >= Self::MAX_PAGES
            || self.page_size.reg.get() < Self::PAGE_SIZE as u32
            || self.file.is_none()
        {
            println!("Erase page failed sanity check");
            return Err(FlashOpError::EraseError);
        }

        // Erase the entire page in the backend file by writing 0xFF.
        if let Some(file) = &mut self.file {
            // Erase the entire page in the backend file
            let offset = (page_num * Self::PAGE_SIZE as u32) as u64;
            if file.seek(std::io::SeekFrom::Start(offset)).is_err()
                || file.write_all(&vec![0xFF; Self::PAGE_SIZE]).is_err()
            {
                println!("Erase page failed: seek or write error");
                return Err(FlashOpError::EraseError);
            }
        }

        Ok(())
    }

    fn process_io(&mut self) {
        // Check if the start bit is set
        if !self.control.reg.is_set(Control::Start) {
            return;
        }

        // Clear ctrl_regwen bit to prevent SW from writing to the control register while the operation is in progress.
        self.ctrl_regwen.reg.modify(CtrlRegwen::En::CLEAR);

        match self.control.reg.read(Control::Op).try_into() {
            Ok(op) => {
                let io_compl = match op {
                    FlashOperation::ReadPage => self.read_page(),
                    FlashOperation::WritePage => self.write_page(),
                    FlashOperation::ErasePage => self.erase_page(),
                };

                self.handle_io_completion(io_compl);
            }
            Err(_) => {
                self.handle_io_completion(Err(FlashOpError::InvalidOp));
            }
        };

        // Enable ctrl_regwen bit to allow SW to write to the control register for the next operation.
        self.ctrl_regwen.reg.modify(CtrlRegwen::En::SET);
    }
}

impl FlashPeripheral for DummyFlashCtrl {
    // Poll the flash controller to process the operation
    fn poll(&mut self) {
        // Check if the operation is pending
        if self.operation_pending {
            self.process_io();
            self.operation_pending = false;
        }
    }

    fn warm_reset(&mut self) {}
    fn update_reset(&mut self) {}

    fn read_interrupt_state(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::flash_ctrl::bits::InterruptState::Register,
    > {
        emulator_bus::ReadWriteRegister::new(self.interrupt_state.reg.get())
    }

    fn write_interrupt_state(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::flash_ctrl::bits::InterruptState::Register,
        >,
    ) {
        // Interrupt state register: write 1 to clear
        if _val.reg.is_set(InterruptState::Error) {
            self.interrupt_state
                .reg
                .modify(InterruptState::Error::CLEAR);
        }
        if _val.reg.is_set(InterruptState::Event) {
            self.interrupt_state
                .reg
                .modify(InterruptState::Event::CLEAR);
        }
    }

    fn read_interrupt_enable(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::flash_ctrl::bits::InterruptEnable::Register,
    > {
        emulator_bus::ReadWriteRegister::new(self.interrupt_enable.reg.get())
    }

    fn write_interrupt_enable(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::flash_ctrl::bits::InterruptEnable::Register,
        >,
    ) {
        self.interrupt_enable.reg.set(_val.reg.get());
    }

    fn write_page_size(&mut self, _size: emulator_types::RvSize, _val: emulator_types::RvData) {
        self.page_size.reg.set(_val);
    }

    // Return the page size of the flash storage connected to the controller
    fn read_page_size(&mut self, _size: emulator_types::RvSize) -> emulator_types::RvData {
        Self::PAGE_SIZE as u32
    }

    fn read_page_num(&mut self, _size: emulator_types::RvSize) -> emulator_types::RvData {
        self.page_num.reg.get()
    }

    fn write_page_num(&mut self, _size: emulator_types::RvSize, _val: emulator_types::RvData) {
        self.page_num.reg.set(_val);
    }

    fn read_page_addr(&mut self, _size: emulator_types::RvSize) -> emulator_types::RvData {
        self.page_addr.reg.get()
    }

    fn write_page_addr(&mut self, _size: emulator_types::RvSize, _val: emulator_types::RvData) {
        self.page_addr.reg.set(_val);
    }

    fn read_control(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::flash_ctrl::bits::Control::Register,
    > {
        emulator_bus::ReadWriteRegister::new(self.control.reg.get())
    }

    // Write to the control register to start the flash operation. The operation is processed in the next cycle.
    fn write_control(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::flash_ctrl::bits::Control::Register,
        >,
    ) {
        self.control.reg.set(_val.reg.get());

        // Set the operation_pending flag to true
        self.operation_pending = true;
    }

    fn read_op_status(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::flash_ctrl::bits::OpStatus::Register,
    > {
        emulator_bus::ReadWriteRegister::new(self.op_status.reg.get())
    }

    fn write_op_status(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::flash_ctrl::bits::OpStatus::Register,
        >,
    ) {
        self.op_status.reg.set(_val.reg.get());
    }

    fn read_ctrl_regwen(
        &mut self,
        _size: emulator_types::RvSize,
    ) -> emulator_bus::ReadWriteRegister<
        u32,
        registers_generated::flash_ctrl::bits::CtrlRegwen::Register,
    > {
        emulator_bus::ReadWriteRegister::new(self.ctrl_regwen.reg.get())
    }

    fn write_ctrl_regwen(
        &mut self,
        _size: emulator_types::RvSize,
        _val: emulator_bus::ReadWriteRegister<
            u32,
            registers_generated::flash_ctrl::bits::CtrlRegwen::Register,
        >,
    ) {
        // Unreacheable
        panic!("Write to read-only ctrl_regwen register");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use core::panic;
    use emulator_bus::{Bus, Clock};
    use emulator_cpu::Pic;
    use emulator_registers_generated::root_bus::AutoRootBus;
    use emulator_types::RvSize;
    use libc::{mmap, munmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
    use registers_generated::flash_ctrl::bits::{
        Control, InterruptEnable, InterruptState, OpStatus,
    };
    use registers_generated::flash_ctrl::FLASH_CTRL_ADDR;
    use std::path::PathBuf;

    pub const INT_STATE_OFFSET: u32 = 0x00;
    pub const INT_ENABLE_OFFSET: u32 = 0x04;
    pub const PAGE_SIZE_OFFSET: u32 = 0x08;
    pub const PAGE_NUM_OFFSET: u32 = 0x0c;
    pub const PAGE_ADDR_OFFSET: u32 = 0x10;
    pub const CONTROL_OFFSET: u32 = 0x14;
    pub const OP_STATUS_OFFSET: u32 = 0x18;

    fn test_helper_setup_autobus(file_path: Option<PathBuf>) -> AutoRootBus {
        let clock = Clock::new();
        let pic = Pic::new();
        let flash_ctrl_error_irq = pic.register_irq(19);
        let flash_ctrl_event_irq = pic.register_irq(20);
        let file = file_path;

        let flash_controller = Box::new(
            DummyFlashCtrl::new(&clock, file, flash_ctrl_error_irq, flash_ctrl_event_irq).unwrap(),
        );

        AutoRootBus::new(None, None, None, None, None, None, Some(flash_controller))
    }

    // helper function to prepare the page buffer for read or write operations
    fn test_helper_prepare_io_page_buffer(
        ref_addr: u32,
        size: usize,
        data: Option<&[u8]>,
    ) -> Option<u32> {
        // Allocate memory within the lower 32-bit address space for the page buffer
        let addr = unsafe {
            mmap(
                ref_addr as *mut libc::c_void,
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            return None;
        }
        // Ensure the address fits within 32-bit address space
        if (addr as usize) > u32::MAX as usize {
            unsafe {
                munmap(addr, size);
            }
            return None;
        }

        // Fill the data into the buffer if provided
        if let Some(data) = data {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    addr as *mut u8,
                    std::cmp::min(data.len(), size),
                );
            }
        }

        Some(addr as u32)
    }

    fn test_helper_release_io_page_buffer(addr: u32, size: usize) {
        unsafe {
            munmap(addr as *mut libc::c_void, size);
        }
    }

    fn test_helper_verify_file_data(
        file_path: &PathBuf,
        page_num: u32,
        expected_data: &[u8],
    ) -> bool {
        let mut file = std::fs::File::open(file_path).unwrap();
        file.seek(std::io::SeekFrom::Start(
            (page_num * DummyFlashCtrl::PAGE_SIZE as u32) as u64,
        ))
        .unwrap();
        let mut file_data = vec![0; DummyFlashCtrl::PAGE_SIZE];
        file.read_exact(&mut file_data).unwrap();
        file_data == expected_data
    }

    fn test_helper_fill_file_with_data(file_path: &PathBuf, page_num: u32, data: &[u8]) {
        let mut file = std::fs::File::options()
            .read(true)
            .write(true)
            .open(file_path)
            .unwrap();
        file.seek(std::io::SeekFrom::Start(
            (page_num * DummyFlashCtrl::PAGE_SIZE as u32) as u64,
        ))
        .unwrap();
        file.write_all(data).unwrap();
    }

    #[test]
    fn test_flash_ctrl_regs_access() {
        // Create a auto root bus
        let mut bus = test_helper_setup_autobus(None);

        // Write to the interrupt enable register and read it back
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + INT_ENABLE_OFFSET,
            InterruptEnable::Error::SET.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_ENABLE_OFFSET)
                .unwrap(),
            InterruptEnable::Error::SET.value
        );

        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + INT_ENABLE_OFFSET,
            InterruptEnable::Event::SET.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_ENABLE_OFFSET)
                .unwrap(),
            InterruptEnable::Event::SET.value
        );

        // Clear the interrupt enable register and read it back
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + INT_ENABLE_OFFSET,
            InterruptEnable::Error::CLEAR.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_ENABLE_OFFSET)
                .unwrap(),
            InterruptEnable::Error::CLEAR.value
        );

        // Write to the interrupt state register and read it back
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + INT_STATE_OFFSET,
            InterruptState::Error::SET.value,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_STATE_OFFSET)
                .unwrap(),
            InterruptState::Error::CLEAR.value
        );

        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + INT_STATE_OFFSET,
            InterruptState::Event::SET.value,
        )
        .unwrap();

        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_STATE_OFFSET)
                .unwrap(),
            InterruptState::Event::CLEAR.value
        );

        // Write to the page size register and read it back
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_SIZE_OFFSET,
            DummyFlashCtrl::PAGE_SIZE as u32,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + PAGE_SIZE_OFFSET)
                .unwrap(),
            DummyFlashCtrl::PAGE_SIZE as u32
        );

        // Write to the page number register and read it back
        bus.write(RvSize::Word, FLASH_CTRL_ADDR + PAGE_NUM_OFFSET, 0x100)
            .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + PAGE_NUM_OFFSET)
                .unwrap(),
            0x100
        );

        // Write to the page address register and read it back
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_ADDR_OFFSET,
            0x1000_0000,
        )
        .unwrap();
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + PAGE_ADDR_OFFSET)
                .unwrap(),
            0x1000_0000
        );

        // read the op_status register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + OP_STATUS_OFFSET)
                .unwrap(),
            0
        );
    }

    #[test]
    fn test_write_page_success() {
        let test_file = PathBuf::from("dummy_flash.bin");
        let test_data = [0xaau8; DummyFlashCtrl::PAGE_SIZE];
        let test_page_num: u32 = 100;

        // Create a auto root bus
        let mut bus = test_helper_setup_autobus(Some(test_file.clone()));

        // Prepare the page buffer for write operation
        let w_page_buf_addr = test_helper_prepare_io_page_buffer(
            0x1000_0000,
            DummyFlashCtrl::PAGE_SIZE,
            Some(&test_data),
        );
        if w_page_buf_addr.is_none() {
            panic!("Error: failed to prepare the page buffer for write operation");
        }

        // Write to the page address register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_ADDR_OFFSET,
            w_page_buf_addr.unwrap(),
        )
        .unwrap();

        // write to the page size register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_SIZE_OFFSET,
            DummyFlashCtrl::PAGE_SIZE as u32,
        )
        .unwrap();

        // write to the page number register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_NUM_OFFSET,
            test_page_num,
        )
        .unwrap();

        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + CONTROL_OFFSET,
            (Control::Start::SET + Control::Op.val(FlashOperation::WritePage as u32)).value,
        )
        .unwrap();

        bus.poll();

        // Check the op_status register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + OP_STATUS_OFFSET)
                .unwrap(),
            OpStatus::Done::SET.value
        );

        // Check the interrupt state register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_STATE_OFFSET)
                .unwrap(),
            InterruptState::Event::SET.value
        );

        assert!(test_helper_verify_file_data(
            &test_file,
            test_page_num,
            &test_data
        ));

        test_helper_release_io_page_buffer(w_page_buf_addr.unwrap(), DummyFlashCtrl::PAGE_SIZE);
    }

    #[test]
    fn test_write_page_error() {
        let test_file = PathBuf::from("dummy_flash.bin");
        let test_data = [0xaau8; DummyFlashCtrl::PAGE_SIZE];
        let test_page_num: u32 = DummyFlashCtrl::MAX_PAGES;

        // Create a auto root bus
        let mut bus = test_helper_setup_autobus(Some(test_file.clone()));

        // Prepare the page buffer for write operation
        let w_page_buf_addr = test_helper_prepare_io_page_buffer(
            0x1001_0000,
            DummyFlashCtrl::PAGE_SIZE,
            Some(&test_data),
        );
        if w_page_buf_addr.is_none() {
            panic!("Error: failed to prepare the page buffer for write operation");
        }

        // Write to the page address register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_ADDR_OFFSET,
            w_page_buf_addr.unwrap(),
        )
        .unwrap();

        // write to the page size register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_SIZE_OFFSET,
            DummyFlashCtrl::PAGE_SIZE as u32,
        )
        .unwrap();

        // write to the page number register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_NUM_OFFSET,
            test_page_num,
        )
        .unwrap();

        // write to the control register with invalid operation
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + CONTROL_OFFSET,
            (Control::Start::SET + Control::Op.val(FlashOperation::ReadPage as u32)).value,
        )
        .unwrap();

        bus.poll();

        // Check the op_status register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + OP_STATUS_OFFSET)
                .unwrap(),
            OpStatus::Err.val(FlashOpError::ReadError as u32).value
        );

        // Check the interrupt state register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_STATE_OFFSET)
                .unwrap(),
            InterruptState::Error::SET.value
        );

        test_helper_release_io_page_buffer(w_page_buf_addr.unwrap(), DummyFlashCtrl::PAGE_SIZE);
    }

    #[test]
    fn test_read_page_success() {
        let test_file = PathBuf::from("dummy_flash.bin");
        let test_data = [0xbbu8; DummyFlashCtrl::PAGE_SIZE];
        let test_page_num: u32 = 50;

        // Create a auto root bus
        let mut bus = test_helper_setup_autobus(Some(test_file.clone()));

        // Fill the test page with test data
        test_helper_fill_file_with_data(&test_file, test_page_num, &test_data);

        // Prepare the page buffer for read operation
        let r_page_buf_addr =
            test_helper_prepare_io_page_buffer(0x1002_0000, DummyFlashCtrl::PAGE_SIZE, None);
        if r_page_buf_addr.is_none() {
            panic!("Error: failed to prepare the page buffer for read operation");
        }

        // Write to the page address register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_ADDR_OFFSET,
            r_page_buf_addr.unwrap(),
        )
        .unwrap();

        // write to the page size register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_SIZE_OFFSET,
            DummyFlashCtrl::PAGE_SIZE as u32,
        )
        .unwrap();

        // write to the page number register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_NUM_OFFSET,
            test_page_num,
        )
        .unwrap();

        // write to the control register with invalid operation
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + CONTROL_OFFSET,
            (Control::Start::SET + Control::Op.val(FlashOperation::ReadPage as u32)).value,
        )
        .unwrap();

        bus.poll();

        // Check the op_status register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + OP_STATUS_OFFSET)
                .unwrap(),
            OpStatus::Done::SET.value
        );

        // Check the interrupt state register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_STATE_OFFSET)
                .unwrap(),
            InterruptState::Event::SET.value
        );

        // Read the data stored in r_page_buf_addr and compare with the test data
        let mut r_page_data = [0u8; DummyFlashCtrl::PAGE_SIZE];
        unsafe {
            std::ptr::copy_nonoverlapping(
                r_page_buf_addr.unwrap() as *const u8,
                r_page_data.as_mut_ptr(),
                DummyFlashCtrl::PAGE_SIZE,
            );
        }

        assert_eq!(r_page_data, test_data);

        test_helper_release_io_page_buffer(r_page_buf_addr.unwrap(), DummyFlashCtrl::PAGE_SIZE);
    }

    #[test]
    fn test_read_page_error() {
        let test_file = PathBuf::from("dummy_flash.bin");
        let test_page_num: u32 = DummyFlashCtrl::MAX_PAGES;

        // Create a auto root bus
        let mut bus = test_helper_setup_autobus(Some(test_file.clone()));

        // Prepare the page buffer for read operation
        let r_page_buf_addr =
            test_helper_prepare_io_page_buffer(0x1003_0000, DummyFlashCtrl::PAGE_SIZE, None);
        if r_page_buf_addr.is_none() {
            panic!("Error: failed to prepare the page buffer for read operation");
        }

        // Write to the page address register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_ADDR_OFFSET,
            r_page_buf_addr.unwrap(),
        )
        .unwrap();

        // write to the page size register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_SIZE_OFFSET,
            DummyFlashCtrl::PAGE_SIZE as u32,
        )
        .unwrap();

        // write to the page number register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_NUM_OFFSET,
            test_page_num,
        )
        .unwrap();

        // write to the control register with invalid operation
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + CONTROL_OFFSET,
            (Control::Start::SET + Control::Op.val(FlashOperation::ReadPage as u32)).value,
        )
        .unwrap();

        bus.poll();

        // Check the op_status register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + OP_STATUS_OFFSET)
                .unwrap(),
            OpStatus::Err.val(FlashOpError::ReadError as u32).value
        );

        // Check the interrupt state register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_STATE_OFFSET)
                .unwrap(),
            InterruptState::Error::SET.value
        );

        test_helper_release_io_page_buffer(r_page_buf_addr.unwrap(), DummyFlashCtrl::PAGE_SIZE);
    }

    #[test]
    fn test_erase_page_success() {
        let test_file = PathBuf::from("dummy_flash.bin");
        let test_page_num: u32 = 300;

        // Create a auto root bus
        let mut bus = test_helper_setup_autobus(Some(test_file.clone()));

        // write to the page number register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_NUM_OFFSET,
            test_page_num,
        )
        .unwrap();

        // write to the page size register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_SIZE_OFFSET,
            DummyFlashCtrl::PAGE_SIZE as u32,
        )
        .unwrap();

        // write to the control register with invalid operation
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + CONTROL_OFFSET,
            (Control::Start::SET + Control::Op.val(FlashOperation::ErasePage as u32)).value,
        )
        .unwrap();

        bus.poll();

        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + OP_STATUS_OFFSET)
                .unwrap(),
            OpStatus::Done::SET.value
        );

        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_STATE_OFFSET)
                .unwrap(),
            InterruptState::Event::SET.value
        );

        // Verify the data in the file. After erasing the page, the data should be all 0xFF
        assert!(test_helper_verify_file_data(
            &test_file,
            test_page_num,
            &[0xFFu8; DummyFlashCtrl::PAGE_SIZE]
        ));
    }

    #[test]
    fn test_erase_page_error() {
        let test_file = PathBuf::from("dummy_flash.bin");
        let test_page_num: u32 = DummyFlashCtrl::MAX_PAGES;

        // Create a auto root bus
        let mut bus = test_helper_setup_autobus(Some(test_file.clone()));

        // write to the page number register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_NUM_OFFSET,
            test_page_num,
        )
        .unwrap();

        // write to the page size register
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + PAGE_SIZE_OFFSET,
            DummyFlashCtrl::PAGE_SIZE as u32,
        )
        .unwrap();

        // write to the control register with invalid operation
        bus.write(
            RvSize::Word,
            FLASH_CTRL_ADDR + CONTROL_OFFSET,
            (Control::Start::SET + Control::Op.val(FlashOperation::ErasePage as u32)).value,
        )
        .unwrap();

        bus.poll();

        // Check the op_status register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + OP_STATUS_OFFSET)
                .unwrap(),
            OpStatus::Err.val(FlashOpError::EraseError as u32).value
        );

        // Check the interrupt state register
        assert_eq!(
            bus.read(RvSize::Word, FLASH_CTRL_ADDR + INT_STATE_OFFSET)
                .unwrap(),
            InterruptState::Error::SET.value
        );
    }
}
