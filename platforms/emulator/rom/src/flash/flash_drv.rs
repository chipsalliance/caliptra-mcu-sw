// Licensed under the Apache-2.0 license

// Emulated flash controller driver for MCU ROM.

use core::fmt::Write;
use core::ops::{Index, IndexMut};
use mcu_rom_common::flash::hil::{FlashDrvError, FlashStorage};
use registers_generated::primary_flash_ctrl::{
    self,
    bits::{CtrlRegwen, FlControl, FlInterruptEnable, FlInterruptState, OpStatus},
    regs::PrimaryFlashCtrl,
};
use romtime::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

#[allow(dead_code)]
pub const PRIMARY_FLASH_CTRL_BASE: StaticRef<PrimaryFlashCtrl> = unsafe {
    StaticRef::new(primary_flash_ctrl::PRIMARY_FLASH_CTRL_ADDR as *const PrimaryFlashCtrl)
};

#[allow(dead_code)]
pub const SECONDARY_FLASH_CTRL_BASE: StaticRef<PrimaryFlashCtrl> = unsafe {
    StaticRef::new(
        registers_generated::secondary_flash_ctrl::SECONDARY_FLASH_CTRL_ADDR
            as *const PrimaryFlashCtrl,
    )
};

const PAGE_SIZE: usize = 256;
const FLASH_MAX_PAGES: usize = 64 * 1024 * 1024 / PAGE_SIZE;

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

#[derive(Debug)]
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

pub struct EmulatedFlashCtrl {
    registers: StaticRef<PrimaryFlashCtrl>,
}

impl FlashStorage for EmulatedFlashCtrl {
    // Read arbitrary length of data from flash, starting at `offset`, into `buf`.
    // Returns Ok(()) on success, or Err(FlashDrvError) on failure.
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<(), FlashDrvError> {
        let mut remaining = buf.len();
        let mut buf_offset = 0;
        let mut flash_offset = offset;
        let mut page_buf = EmulatedFlashPage::default();

        while remaining > 0 {
            let page_number = flash_offset / PAGE_SIZE;
            let page_offset = flash_offset % PAGE_SIZE;
            let to_read = core::cmp::min(PAGE_SIZE - page_offset, remaining);

            // Read the page into page_buf
            self.read_page(page_number, &mut page_buf)?;

            let dst = buf
                .get_mut(buf_offset..buf_offset + to_read)
                .ok_or(FlashDrvError::INVAL)?;
            let src = page_buf
                .0
                .get(page_offset..page_offset + to_read)
                .ok_or(FlashDrvError::INVAL)?;
            for (d, s) in dst.iter_mut().zip(src.iter()) {
                *d = *s;
            }

            remaining -= to_read;
            buf_offset += to_read;
            flash_offset += to_read;
        }

        Ok(())
    }

    // Write arbitrary length of data to flash, starting at `offset`, from `buf`.
    // Returns Ok(()) on success, or Err(FlashDrvError) on failure.
    fn write(&self, buf: &[u8], offset: usize) -> Result<(), FlashDrvError> {
        let mut remaining = buf.len();
        let mut buf_offset = 0;
        let mut flash_offset = offset;

        while remaining > 0 {
            let page_number = flash_offset / PAGE_SIZE;
            let page_offset = flash_offset % PAGE_SIZE;
            let to_write = core::cmp::min(PAGE_SIZE - page_offset, remaining);

            // Read the page first if not writing the whole page
            let mut page_buf = if to_write != PAGE_SIZE {
                let mut tmp = EmulatedFlashPage::default();
                self.read_page(page_number, &mut tmp)?;
                tmp
            } else {
                EmulatedFlashPage::default()
            };

            let dst = page_buf
                .0
                .get_mut(page_offset..page_offset + to_write)
                .ok_or(FlashDrvError::INVAL)?;
            let src = buf
                .get(buf_offset..buf_offset + to_write)
                .ok_or(FlashDrvError::INVAL)?;
            for (d, s) in dst.iter_mut().zip(src.iter()) {
                *d = *s;
            }

            self.write_page(page_number, &mut page_buf)?;

            remaining -= to_write;
            buf_offset += to_write;
            flash_offset += to_write;
        }

        Ok(())
    }

    // Erase arbitrary length of data in flash, starting at `offset`, for `len` bytes.
    // Returns Ok(()) on success, or Err(FlashDrvError) on failure.
    fn erase(&self, offset: usize, len: usize) -> Result<(), FlashDrvError> {
        if len == 0 {
            return Ok(());
        }
        let start_page = offset / PAGE_SIZE;
        let end_page = (offset + len - 1) / PAGE_SIZE;

        for page in start_page..=end_page {
            self.erase_page(page)?;
        }
        Ok(())
    }

    fn capacity(&self) -> usize {
        FLASH_MAX_PAGES * PAGE_SIZE
    }
}

#[allow(dead_code)]
impl EmulatedFlashCtrl {
    pub fn initialize_flash_ctrl(base: StaticRef<PrimaryFlashCtrl>) -> EmulatedFlashCtrl {
        let ctrl = EmulatedFlashCtrl { registers: base };
        ctrl.init();
        ctrl
    }

    fn init(&self) {
        self.registers
            .op_status
            .modify(OpStatus::Err::CLEAR + OpStatus::Done::CLEAR);

        self.clear_error_interrupt();
        self.clear_event_interrupt();
    }

    fn read_page(
        &self,
        page_number: usize,
        buf: &mut EmulatedFlashPage,
    ) -> Result<(), FlashDrvError> {
        // Check if the page number is valid
        if page_number >= FLASH_MAX_PAGES {
            return Err(FlashDrvError::INVAL);
        }

        // Check ctrl_regwen status before we commit
        if !self.registers.ctrl_regwen.is_set(CtrlRegwen::En) {
            return Err(FlashDrvError::BUSY);
        }

        // Clear the control register
        self.registers
            .fl_control
            .modify(FlControl::Op::CLEAR + FlControl::Start::CLEAR);

        let page_buf_addr = buf.as_mut().as_ptr() as u32;
        let page_buf_len = buf.as_mut().len() as u32;

        // Program page_num, page_addr, page_size registers
        self.registers.page_num.set(page_number as u32);
        self.registers.page_addr.set(page_buf_addr);
        self.registers.page_size.set(page_buf_len);

        // Enable interrupts
        self.enable_interrupts();

        // Start the read operation
        self.registers
            .fl_control
            .modify(FlControl::Op.val(FlashOperation::ReadPage as u32) + FlControl::Start::SET);

        // Polling for the operation to complete. This is a blocking call.
        self.poll_for_completion()
    }

    fn write_page(
        &self,
        page_number: usize,
        buf: &mut EmulatedFlashPage,
    ) -> Result<(), FlashDrvError> {
        // Check if the page number is valid
        if page_number >= FLASH_MAX_PAGES {
            return Err(FlashDrvError::INVAL);
        }

        // Check ctrl_regwen status before we commit
        if !self.registers.ctrl_regwen.is_set(CtrlRegwen::En) {
            return Err(FlashDrvError::BUSY);
        }

        // Clear the control register
        self.registers
            .fl_control
            .modify(FlControl::Op::CLEAR + FlControl::Start::CLEAR);

        let page_buf_addr = buf.as_mut().as_ptr() as u32;
        let page_buf_len = buf.as_mut().len() as u32;

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

        // Polling for the operation to complete. This is a blocking call.
        self.poll_for_completion()
    }

    fn erase_page(&self, page_number: usize) -> Result<(), FlashDrvError> {
        if page_number >= FLASH_MAX_PAGES {
            return Err(FlashDrvError::INVAL);
        }

        // Check ctrl_regwen status before we commit
        if !self.registers.ctrl_regwen.is_set(CtrlRegwen::En) {
            return Err(FlashDrvError::BUSY);
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

        // Polling for the operation to complete. This is a blocking call.
        self.poll_for_completion()
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

    fn poll_for_completion(&self) -> Result<(), FlashDrvError> {
        loop {
            let flashctrl_intr = self.registers.fl_interrupt_state.extract();

            // Handling event interrupt (normal completion)
            if flashctrl_intr.is_set(FlInterruptState::Event) {
                // Clear the op_status register
                self.registers.op_status.modify(OpStatus::Done::CLEAR);
                self.clear_event_interrupt();
                self.disable_interrupts();
                return Ok(());
            }

            // Handling error interrupt
            if flashctrl_intr.is_set(FlInterruptState::Error) {
                // Clear the op_status register
                self.registers.op_status.modify(OpStatus::Err::CLEAR);
                self.clear_error_interrupt();
                self.disable_interrupts();

                romtime::println!("Flash IO failed");
                return Err(FlashDrvError::FAIL);
            }
        }
    }
}
