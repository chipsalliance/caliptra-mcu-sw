// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use core::ops::{Index, IndexMut};
use kernel::hil;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::ErrorCode;
use registers_generated::primary_flash_ctrl::{
    bits::{CtrlRegwen, FlControl, FlInterruptEnable, FlInterruptState, OpStatus},
    regs::PrimaryFlashCtrl,
    PRIMARY_FLASH_CTRL_ADDR,
};
use registers_generated::secondary_flash_ctrl::SECONDARY_FLASH_CTRL_ADDR;

// The recovery flash controller is identical to the main flash controller in the emulator.
// Both controllers use the same register structures, differing only in their base addresses.
// Therefore, we can use PrimaryFlashCtrl to represent both flash controllers.
pub const PRIMARY_FLASH_CTRL_BASE: StaticRef<PrimaryFlashCtrl> =
    unsafe { StaticRef::new(PRIMARY_FLASH_CTRL_ADDR as *const PrimaryFlashCtrl) };
pub const SECONDARY_FLASH_CTRL_BASE: StaticRef<PrimaryFlashCtrl> =
    unsafe { StaticRef::new(SECONDARY_FLASH_CTRL_ADDR as *const PrimaryFlashCtrl) };

pub const PAGE_SIZE: usize = 256;
pub const FLASH_MAX_PAGES: usize = 64 * 1024 * 1024 / PAGE_SIZE;

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

pub struct EmulatedFlashCtrl<'a> {
    registers: StaticRef<PrimaryFlashCtrl>,
    flash_client: OptionalCell<&'a dyn hil::flash::Client<EmulatedFlashCtrl<'a>>>,
    read_buf: TakeCell<'static, EmulatedFlashPage>,
    write_buf: TakeCell<'static, EmulatedFlashPage>,
}

impl<'a> EmulatedFlashCtrl<'a> {
    pub fn new(base: StaticRef<PrimaryFlashCtrl>) -> EmulatedFlashCtrl<'a> {
        EmulatedFlashCtrl {
            registers: base,
            flash_client: OptionalCell::empty(),
            read_buf: TakeCell::empty(),
            write_buf: TakeCell::empty(),
        }
    }

    pub fn init(&self) {
        self.registers
            .op_status
            .modify(OpStatus::Err::CLEAR + OpStatus::Done::CLEAR);

        self.clear_error_interrupt();
        self.clear_event_interrupt();
    }

    fn enable_interrupts(&self) {
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
        // Clear the error interrupt. Write 1 to clear
        self.registers
            .fl_interrupt_state
            .modify(FlInterruptState::Error::SET);
    }

    fn clear_event_interrupt(&self) {
        // Clear the event interrupt. Write 1 to clear
        self.registers
            .fl_interrupt_state
            .modify(FlInterruptState::Event::SET);
    }

    pub fn handle_interrupt(&self) {
        let flashctrl_intr = self.registers.fl_interrupt_state.extract();

        self.disable_interrupts();

        // Handling error interrupt
        if flashctrl_intr.is_set(FlInterruptState::Error) {
            // Clear the op_status register
            self.registers.op_status.modify(OpStatus::Err::CLEAR);

            self.clear_error_interrupt();

            let read_buf = self.read_buf.take();
            if let Some(buf) = read_buf {
                // We were doing a read
                self.flash_client.map(move |client| {
                    client.read_complete(buf, Err(hil::flash::Error::FlashError));
                });
            }

            let write_buf = self.write_buf.take();
            if let Some(buf) = write_buf {
                // We were doing a write
                self.flash_client.map(move |client| {
                    client.write_complete(buf, Err(hil::flash::Error::FlashError));
                });
            }

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
        }

        // Handling event interrupt (normal completion)
        if flashctrl_intr.is_set(FlInterruptState::Event) {
            // Clear the op_status register
            self.registers.op_status.modify(OpStatus::Done::CLEAR);

            // Clear the interrupt before callback as it is possible that the callback will start another operation.
            // Otherwise, emulated flash ctrl won't allow starting another operation if the previous one is not cleared.
            self.clear_event_interrupt();

            if self
                .registers
                .fl_control
                .matches_all(FlControl::Op.val(FlashOperation::ReadPage as u32))
            {
                let read_buf = self.read_buf.take();
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

        let page_buf_addr = buf.as_mut().as_ptr() as u32;
        let page_buf_len = buf.as_mut().len() as u32;

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

        // Extract necessary information from buf before replacing it
        let page_buf_addr = buf.as_mut().as_ptr() as u32;
        let page_buf_len = buf.as_mut().len() as u32;

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
