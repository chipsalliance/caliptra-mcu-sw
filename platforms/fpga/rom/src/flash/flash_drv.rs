// Licensed under the Apache-2.0 license

// FPGA flash controller driver for MCU ROM.
// This is a simplified version of the emulator's flash driver, but contains
// only the parts that the FPGA model implements.

use core::ops::{Index, IndexMut};
use mcu_rom_common::flash::hil::{FlashDrvError, FlashStorage};
use registers_generated::primary_flash_ctrl::{
    bits::{FlControl, OpStatus},
    regs::PrimaryFlashCtrl,
};
use romtime::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

/// FPGA wrapper primary flash controller address
pub const FPGA_PRIMARY_FLASH_CTRL_ADDR: u32 = 0xA401_2000;

/// FPGA wrapper secondary flash controller address
pub const FPGA_SECONDARY_FLASH_CTRL_ADDR: u32 = 0xA401_3000;

/// Fixed SRAM buffer for flash page operations
pub const FLASH_PAGE_BUFFER_SRAM_OFFSET: u32 = 0xA401_2100;

#[allow(dead_code)]
pub const PRIMARY_FLASH_CTRL_BASE: StaticRef<PrimaryFlashCtrl> =
    unsafe { StaticRef::new(FPGA_PRIMARY_FLASH_CTRL_ADDR as *const PrimaryFlashCtrl) };

#[allow(dead_code)]
pub const SECONDARY_FLASH_CTRL_BASE: StaticRef<PrimaryFlashCtrl> =
    unsafe { StaticRef::new(FPGA_SECONDARY_FLASH_CTRL_ADDR as *const PrimaryFlashCtrl) };

// FPGA uses a fixed page size of 256 bytes
const PAGE_SIZE: usize = 256;
const FLASH_MAX_PAGES: usize = 16 * 1024 * 1024 / PAGE_SIZE;

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
pub struct FpgaFlashPage(pub [u8; PAGE_SIZE]);

impl Default for FpgaFlashPage {
    fn default() -> Self {
        Self([0; PAGE_SIZE])
    }
}

impl Index<usize> for FpgaFlashPage {
    type Output = u8;

    fn index(&self, idx: usize) -> &u8 {
        &self.0[idx]
    }
}

impl IndexMut<usize> for FpgaFlashPage {
    fn index_mut(&mut self, idx: usize) -> &mut u8 {
        &mut self.0[idx]
    }
}

impl AsMut<[u8]> for FpgaFlashPage {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

pub struct FpgaFlashCtrl {
    registers: StaticRef<PrimaryFlashCtrl>,
}

impl FlashStorage for FpgaFlashCtrl {
    // Read arbitrary length of data from flash, starting at `offset`, into `buf`.
    // Returns Ok(()) on success, or Err(FlashDrvError) on failure.
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<(), FlashDrvError> {
        let mut remaining = buf.len();
        let mut buf_offset = 0;
        let mut flash_offset = offset;
        let mut page_buf = FpgaFlashPage::default();

        while remaining > 0 {
            let page_number = flash_offset / PAGE_SIZE;
            let page_offset = flash_offset % PAGE_SIZE;
            let to_read = core::cmp::min(PAGE_SIZE - page_offset, remaining);

            // Read the page into page_buf
            self.read_page(page_number, &mut page_buf)?;

            buf[buf_offset..buf_offset + to_read]
                .copy_from_slice(&page_buf.0[page_offset..page_offset + to_read]);

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
                let mut tmp = FpgaFlashPage::default();
                self.read_page(page_number, &mut tmp)?;
                tmp
            } else {
                FpgaFlashPage::default()
            };

            page_buf.0[page_offset..page_offset + to_write]
                .copy_from_slice(&buf[buf_offset..buf_offset + to_write]);

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
impl FpgaFlashCtrl {
    pub fn initialize_flash_ctrl(base: StaticRef<PrimaryFlashCtrl>) -> FpgaFlashCtrl {
        let ctrl = FpgaFlashCtrl { registers: base };
        ctrl.init();
        ctrl
    }

    /// Returns the total capacity of the flash in bytes.
    pub fn capacity(&self) -> usize {
        FLASH_MAX_PAGES * PAGE_SIZE
    }

    fn init(&self) {
        self.registers
            .op_status
            .modify(OpStatus::Err::CLEAR + OpStatus::Done::CLEAR);
    }

    fn read_page(&self, page_number: usize, buf: &mut FpgaFlashPage) -> Result<(), FlashDrvError> {
        // Check if the page number is valid
        if page_number >= FLASH_MAX_PAGES {
            return Err(FlashDrvError::INVAL);
        }

        // Clear the control register
        self.registers
            .fl_control
            .modify(FlControl::Op::CLEAR + FlControl::Start::CLEAR);

        // Use the fixed SRAM buffer address for FPGA
        let page_buf_addr = FLASH_PAGE_BUFFER_SRAM_OFFSET;

        // Program page_num, page_addr registers (page_size is fixed on FPGA)
        self.registers.page_num.set(page_number as u32);

        // Start the read operation
        self.registers
            .fl_control
            .modify(FlControl::Op.val(FlashOperation::ReadPage as u32) + FlControl::Start::SET);

        // Polling for the operation to complete. This is a blocking call.
        self.poll_for_completion()?;

        // Copy data from SRAM buffer to the provided buffer
        let sram_ptr = page_buf_addr as *const u8;
        unsafe {
            for i in 0..PAGE_SIZE {
                buf.0[i] = core::ptr::read_volatile(sram_ptr.add(i));
            }
        }

        Ok(())
    }

    fn write_page(&self, page_number: usize, buf: &mut FpgaFlashPage) -> Result<(), FlashDrvError> {
        // Check if the page number is valid
        if page_number >= FLASH_MAX_PAGES {
            return Err(FlashDrvError::INVAL);
        }

        // Clear the control register
        self.registers
            .fl_control
            .modify(FlControl::Op::CLEAR + FlControl::Start::CLEAR);

        // Use the fixed SRAM buffer address for FPGA
        let page_buf_addr = FLASH_PAGE_BUFFER_SRAM_OFFSET;

        // Copy data from the provided buffer to SRAM buffer
        let sram_ptr = page_buf_addr as *mut u8;
        unsafe {
            for i in 0..PAGE_SIZE {
                core::ptr::write_volatile(sram_ptr.add(i), buf.0[i]);
            }
        }

        // Program page_num, page_addr registers (page_size is fixed on FPGA)
        self.registers.page_num.set(page_number as u32);

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

        // Clear the control register
        self.registers
            .fl_control
            .modify(FlControl::Op::CLEAR + FlControl::Start::CLEAR);

        // Program page_num register
        self.registers.page_num.set(page_number as u32);

        // Start the erase operation
        self.registers
            .fl_control
            .modify(FlControl::Op.val(FlashOperation::ErasePage as u32) + FlControl::Start::SET);

        // Polling for the operation to complete. This is a blocking call.
        self.poll_for_completion()
    }

    fn poll_for_completion(&self) -> Result<(), FlashDrvError> {
        while self.registers.op_status.read(OpStatus::Done) == 0 {}
        self.registers.op_status.modify(OpStatus::Done::CLEAR);
        if self.registers.op_status.read(OpStatus::Err) != 0 {
            Err(FlashDrvError::FAIL)
        } else {
            Ok(())
        }
    }
}
