// Licensed under the Apache-2.0 license

// Flash controller driver for the dummy flash controller in the emulator
// This driver will implment kernel::hil::flash::Flash trait and will be used by the kernel

use core::ops::{Index, IndexMut};
use kernel::debug;
use kernel::hil;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::ErrorCode;

// XS: adding for debug print
use core::fmt::Write;
use romtime::println;

use registers_generated::flash_ctrl::{
    bits::{CtrlRegwen, FlControl, FlInterruptEnable, FlInterruptState, OpStatus},
    regs::FlashCtrl,
    FLASH_CTRL_ADDR,
};

pub const FLASH_CTRL_BASE: StaticRef<FlashCtrl> =
    unsafe { StaticRef::new(FLASH_CTRL_ADDR as *const FlashCtrl) };

pub const PAGE_SIZE: usize = 1024;
pub const FLASH_MAX_PAGES: usize = 64 * 1024;

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

// Define Emulated Flash Page Size Struct
pub struct EmulatedFlashPage(pub [u8; PAGE_SIZE]);

impl Default for EmulatedFlashPage {
    fn default() -> Self {
        Self([0; PAGE_SIZE])
    }
}

impl Index<usize> for EmulatedFlashPage {
    type Output = u8;

    fn index(&self, idx: usize) -> &u8 {
        &self.0[idx]
    }
}

impl IndexMut<usize> for EmulatedFlashPage {
    fn index_mut(&mut self, idx: usize) -> &mut u8 {
        &mut self.0[idx]
    }
}

impl AsMut<[u8]> for EmulatedFlashPage {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// Define the interface for the flash controller driver
pub struct EmulatedFlashCtrl<'a> {
    registers: StaticRef<FlashCtrl>,
    flash_client: OptionalCell<&'a dyn hil::flash::Client<EmulatedFlashCtrl<'a>>>,
    read_buf: TakeCell<'static, EmulatedFlashPage>,
    write_buf: TakeCell<'static, EmulatedFlashPage>,
}

impl<'a> EmulatedFlashCtrl<'a> {
    pub fn new(base: StaticRef<FlashCtrl>) -> EmulatedFlashCtrl<'a> {
        EmulatedFlashCtrl {
            registers: base,
            flash_client: OptionalCell::empty(),
            read_buf: TakeCell::empty(),
            write_buf: TakeCell::empty(),
        }
    }

    pub fn init(&self) {
        // Clear op status register
        self.registers
            .op_status
            .modify(OpStatus::Err::CLEAR + OpStatus::Done::CLEAR);

        // Clear interrupt state register
        self.registers
            .fl_interrupt_state
            .modify(FlInterruptState::Error::SET + FlInterruptState::Event::SET);
    }

    fn enable_interrupts(&self) {
        // Enable relevent interrupts
        self.registers
            .fl_interrupt_enable
            .modify(FlInterruptEnable::Error::SET + FlInterruptEnable::Event::SET);
    }

    fn disable_interrupts(&self) {
        self.registers
            .fl_interrupt_enable
            .modify(FlInterruptEnable::Error::CLEAR + FlInterruptEnable::Event::CLEAR);
    }

    fn clear_error_interrupt(&self) {
        self.registers
            .fl_interrupt_state
            .modify(FlInterruptState::Error::SET);
    }

    fn clear_event_interrupt(&self) {
        self.registers
            .fl_interrupt_state
            .modify(FlInterruptState::Event::SET);
    }

    pub fn handle_interrupt(&self) {
        println!("[xs debug]driver:FlashCtrl interrupt handler");

        // Extract the interrupt state and save it
        let flashctrl_intr = self.registers.fl_interrupt_state.extract();

        self.disable_interrupts();

        // If it's error interrupt, call the client's error handler
        if flashctrl_intr.is_set(FlInterruptState::Error) {
            // Clear the op_status register
            self.registers.op_status.modify(OpStatus::Err::CLEAR);

            let read_buf = self.read_buf.take();
            // Check if this is read error
            if let Some(buf) = read_buf {
                // We were doing a read
                self.flash_client.map(move |client| {
                    client.read_complete(buf, Err(hil::flash::Error::FlashError));
                });
            }

            let write_buf = self.write_buf.take();
            // Check if this is write error
            if let Some(buf) = write_buf {
                // We were doing a write
                self.flash_client.map(move |client| {
                    client.write_complete(buf, Err(hil::flash::Error::FlashError));
                });
            }

            // Check if this is an erase operation
            if self
                .registers
                .fl_control
                .matches_all(FlControl::Op.val(FlashOperation::ErasePage as u32))
            {
                // We were doing an erase
                self.flash_client.map(move |client| {
                    client.erase_complete(Err(hil::flash::Error::FlashError));
                });
            }

            self.clear_error_interrupt();
        }

        // If it's event interrupt, call the client's event handler
        if flashctrl_intr.is_set(FlInterruptState::Event) {
            // Clear the op_status register
            self.registers.op_status.modify(OpStatus::Done::CLEAR);

            if self
                .registers
                .fl_control
                .matches_all(FlControl::Op.val(FlashOperation::ReadPage as u32))
            {
                let read_buf = self.read_buf.take();
                // Check if this is read event
                if let Some(buf) = read_buf {
                    // We were doing a read
                    self.flash_client.map(move |client| {
                        client.read_complete(buf, Ok(()));
                    });
                }
            } else if self
                .registers
                .fl_control
                .matches_all(FlControl::Op.val(FlashOperation::WritePage as u32))
            {
                let write_buf = self.write_buf.take();
                // Check if this is write event
                if let Some(buf) = write_buf {
                    // We were doing a write
                    self.flash_client.map(move |client| {
                        client.write_complete(buf, Ok(()));
                    });
                }
            } else if self
                .registers
                .fl_control
                .matches_all(FlControl::Op.val(FlashOperation::ErasePage as u32))
            {
                // We were doing an erase
                self.flash_client.map(move |client| {
                    client.erase_complete(Ok(()));
                });
            }

            // Clear the interrupt state register event bit. Write 1 to clear
            self.clear_event_interrupt();
        }
    }
}

impl<C: hil::flash::Client<Self>> hil::flash::HasClient<'static, C> for EmulatedFlashCtrl<'_> {
    fn set_client(&self, client: &'static C) {
        self.flash_client.set(client);
    }
}

impl hil::flash::Flash for EmulatedFlashCtrl<'_> {
    type Page = EmulatedFlashPage;

    fn read_page(
        &self,
        page_number: usize,
        buf: &'static mut Self::Page,
    ) -> Result<(), (ErrorCode, &'static mut Self::Page)> {
        // Check if the page number is valid
        if page_number >= FLASH_MAX_PAGES {
            return Err((ErrorCode::INVAL, buf));
        }

        // Check ctrl_regwen status before we commit
        if !self.registers.ctrl_regwen.is_set(CtrlRegwen::En) {
            return Err((ErrorCode::BUSY, buf));
        }

        // Clear the control register
        self.registers
            .fl_control
            .modify(FlControl::Op::CLEAR + FlControl::Start::CLEAR);

        // panic if buf address is above 32-bit address space
        if buf.as_mut().as_ptr() as usize > u32::MAX as usize {
            panic!(
                "Buffer address {:p} is above 32-bit address space",
                buf.as_mut().as_ptr()
            );
        }

        // Extract necessary information from buf before replacing it
        let page_buf_addr = buf.as_mut().as_ptr() as u32;
        let page_buf_len = buf.as_mut().len() as u32;

        // debug print the page number, page address and page size
        debug!(
            "Page Number: {}, Page Address: {:#010x}, Page Size: {}",
            page_number, page_buf_addr, page_buf_len
        );

        // Save the buffer
        self.read_buf.replace(buf);

        // Program page_num, page_addr, page_size registers
        self.registers.page_num.set(page_number as u32);

        // Page addr is the buffer address
        self.registers.page_addr.set(page_buf_addr);

        // Page size is the size of the buffer
        self.registers.page_size.set(page_buf_len);

        // Enable interrupts
        self.enable_interrupts();

        // Start the read operation
        self.registers
            .fl_control
            .modify(FlControl::Op.val(FlashOperation::ReadPage as u32) + FlControl::Start::SET);

        Ok(())
    }

    fn write_page(
        &self,
        page_number: usize,
        buf: &'static mut Self::Page,
    ) -> Result<(), (ErrorCode, &'static mut Self::Page)> {
        println!("[xs debug]flash driver: write_page start");

        // Check if the page number is valid
        if page_number >= FLASH_MAX_PAGES {
            return Err((ErrorCode::INVAL, buf));
        }

        // Check ctrl_regwen status before we commit
        if !self.registers.ctrl_regwen.is_set(CtrlRegwen::En) {
            return Err((ErrorCode::BUSY, buf));
        }

        // Clear the control register
        self.registers
            .fl_control
            .modify(FlControl::Op::CLEAR + FlControl::Start::CLEAR);

        // panic if buf address is above 32-bit address space
        if buf.as_mut().as_ptr() as usize > u32::MAX as usize {
            panic!(
                "Buffer address {:p} is above 32-bit address space",
                buf.as_mut().as_ptr()
            );
        }

        // Extract necessary information from buf before replacing it
        let page_buf_addr = buf.as_mut().as_ptr() as u32;
        let page_buf_len = buf.as_mut().len() as u32;

        // debug print the page number, page address and page size
        println!(
            "[xs debug]flash driver: Page Number: {}, Page Address: {:#010x}, Page Size: {}",
            page_number, page_buf_addr, page_buf_len
        );

        // Save the buffer
        self.write_buf.replace(buf);

        // Program page_num, page_addr, page_size registers
        self.registers.page_num.set(page_number as u32);
        self.registers.page_addr.set(page_buf_addr);
        self.registers.page_size.set(page_buf_len);

        // Enable interrupts
        self.enable_interrupts();

        // Start the write operation
        self.registers
            .fl_control
            .modify(FlControl::Op.val(FlashOperation::WritePage as u32) + FlControl::Start::SET);

        Ok(())
    }

    fn erase_page(&self, page_number: usize) -> Result<(), ErrorCode> {
        println!("[xs debug]flash driver: erase_page start\n");

        if page_number >= FLASH_MAX_PAGES {
            return Err(ErrorCode::INVAL);
        }

        // Check ctrl_regwen status before we commit
        if !self.registers.ctrl_regwen.is_set(CtrlRegwen::En) {
            return Err(ErrorCode::BUSY);
        }

        // Clear the control register
        self.registers
            .fl_control
            .modify(FlControl::Op::CLEAR + FlControl::Start::CLEAR);

        // Program page_num register
        self.registers.page_num.set(page_number as u32);

        // Program page_size register
        self.registers.page_size.set(PAGE_SIZE as u32);

        // Enable interrupts
        self.enable_interrupts();

        // Start the erase operation
        self.registers
            .fl_control
            .modify(FlControl::Op.val(FlashOperation::ErasePage as u32) + FlControl::Start::SET);

        Ok(())
    }
}
