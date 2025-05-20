// Licensed under the Apache-2.0 license

// File contains flash driver used by MCU ROM.

use core::fmt::Write;
use core::ops::{Index, IndexMut};
use registers_generated::main_flash_ctrl::{
    bits::{CtrlRegwen, FlControl, FlInterruptEnable, FlInterruptState, OpStatus},
    regs::MainFlashCtrl,
};

use romtime::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum ErrorCode {
    // Reserved value, for when "no error" / "success" should be
    // encoded in the same numeric representation as ErrorCode
    //
    // Ok(()) = 0,
    /// Generic failure condition
    FAIL = 1,
    /// Underlying system is busy; retry
    BUSY = 2,
    /// The state requested is already set
    ALREADY = 3,
    /// The component is powered down
    OFF = 4,
    /// Reservation required before use
    RESERVE = 5,
    /// An invalid parameter was passed
    INVAL = 6,
    /// Parameter passed was too large
    SIZE = 7,
    /// Operation canceled by a call
    CANCEL = 8,
    /// Memory required not available
    NOMEM = 9,
    /// Operation is not supported
    NOSUPPORT = 10,
    /// Device is not available
    NODEVICE = 11,
    /// Device is not physically installed
    UNINSTALLED = 12,
    /// Packet transmission not acknowledged
    NOACK = 13,
}

impl From<ErrorCode> for usize {
    fn from(err: ErrorCode) -> usize {
        err as usize
    }
}

impl TryFrom<Result<(), ErrorCode>> for ErrorCode {
    type Error = ();

    fn try_from(rc: Result<(), ErrorCode>) -> Result<Self, Self::Error> {
        match rc {
            Ok(()) => Err(()),
            Err(ErrorCode::FAIL) => Ok(ErrorCode::FAIL),
            Err(ErrorCode::BUSY) => Ok(ErrorCode::BUSY),
            Err(ErrorCode::ALREADY) => Ok(ErrorCode::ALREADY),
            Err(ErrorCode::OFF) => Ok(ErrorCode::OFF),
            Err(ErrorCode::RESERVE) => Ok(ErrorCode::RESERVE),
            Err(ErrorCode::INVAL) => Ok(ErrorCode::INVAL),
            Err(ErrorCode::SIZE) => Ok(ErrorCode::SIZE),
            Err(ErrorCode::CANCEL) => Ok(ErrorCode::CANCEL),
            Err(ErrorCode::NOMEM) => Ok(ErrorCode::NOMEM),
            Err(ErrorCode::NOSUPPORT) => Ok(ErrorCode::NOSUPPORT),
            Err(ErrorCode::NODEVICE) => Ok(ErrorCode::NODEVICE),
            Err(ErrorCode::UNINSTALLED) => Ok(ErrorCode::UNINSTALLED),
            Err(ErrorCode::NOACK) => Ok(ErrorCode::NOACK),
        }
    }
}

impl From<ErrorCode> for Result<(), ErrorCode> {
    fn from(ec: ErrorCode) -> Self {
        match ec {
            ErrorCode::FAIL => Err(ErrorCode::FAIL),
            ErrorCode::BUSY => Err(ErrorCode::BUSY),
            ErrorCode::ALREADY => Err(ErrorCode::ALREADY),
            ErrorCode::OFF => Err(ErrorCode::OFF),
            ErrorCode::RESERVE => Err(ErrorCode::RESERVE),
            ErrorCode::INVAL => Err(ErrorCode::INVAL),
            ErrorCode::SIZE => Err(ErrorCode::SIZE),
            ErrorCode::CANCEL => Err(ErrorCode::CANCEL),
            ErrorCode::NOMEM => Err(ErrorCode::NOMEM),
            ErrorCode::NOSUPPORT => Err(ErrorCode::NOSUPPORT),
            ErrorCode::NODEVICE => Err(ErrorCode::NODEVICE),
            ErrorCode::UNINSTALLED => Err(ErrorCode::UNINSTALLED),
            ErrorCode::NOACK => Err(ErrorCode::NOACK),
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
    registers: StaticRef<MainFlashCtrl>,
}

impl EmulatedFlashCtrl {
    pub fn new(base: StaticRef<MainFlashCtrl>) -> EmulatedFlashCtrl {
        EmulatedFlashCtrl {
            registers: base,
            //read_buf: TakeCell::empty(),
            //write_buf: TakeCell::empty(),
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
}
impl EmulatedFlashCtrl {
    pub fn read_page(
        &self,
        page_number: usize,
        buf: &mut EmulatedFlashPage,
    ) -> Result<(), ErrorCode> {
        romtime::println!("[xs debug]ROM flash driver: Reading page {}", page_number);
        // Check if the page number is valid
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

    pub fn write_page(
        &self,
        page_number: usize,
        buf: &mut EmulatedFlashPage,
    ) -> Result<(), ErrorCode> {
        romtime::println!("[xs debug]ROM flash driver: write page {}", page_number);
        // Check if the page number is valid
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

    pub fn erase_page(&self, page_number: usize) -> Result<(), ErrorCode> {
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

        self.poll_for_completion()
    }

    // Polls for completion of the current flash operation.
    // Returns Ok(()) if the operation completed successfully, or Err(ErrorCode) if an error occurred.
    pub fn poll_for_completion(&self) -> Result<(), ErrorCode> {
        loop {
            let flashctrl_intr = self.registers.fl_interrupt_state.extract();

            // Handling event interrupt (normal completion)
            if flashctrl_intr.is_set(FlInterruptState::Event) {
                // Clear the op_status register
                self.registers.op_status.modify(OpStatus::Done::CLEAR);
                self.clear_event_interrupt();
                self.disable_interrupts();

                romtime::println!("[xs debug]poll_for_completion: Operation complete");
                return Ok(());
            }

            // Handling error interrupt
            if flashctrl_intr.is_set(FlInterruptState::Error) {
                // Clear the op_status register
                self.registers.op_status.modify(OpStatus::Err::CLEAR);
                self.clear_error_interrupt();
                self.disable_interrupts();

                romtime::println!("Flash IO failed");
                return Err(ErrorCode::FAIL);
            }
        }
    }
}
/// Read arbitrary length of data from flash, starting at `offset`, into `buf`.
/// Returns Ok(()) on success, or Err(ErrorCode) on failure.
pub fn flash_read(
    driver: &EmulatedFlashCtrl,
    offset: usize,
    buf: &mut [u8],
) -> Result<(), ErrorCode> {
    let mut remaining = buf.len();
    let mut buf_offset = 0;
    let mut flash_offset = offset;
    let mut page_buf = EmulatedFlashPage::default();

    while remaining > 0 {
        let page_number = flash_offset / PAGE_SIZE;
        let page_offset = flash_offset % PAGE_SIZE;
        let to_read = core::cmp::min(PAGE_SIZE - page_offset, remaining);

        // Read the page into page_buf
        driver.read_page(page_number, &mut page_buf)?;

        buf[buf_offset..buf_offset + to_read]
            .copy_from_slice(&page_buf.0[page_offset..page_offset + to_read]);

        remaining -= to_read;
        buf_offset += to_read;
        flash_offset += to_read;
    }
    Ok(())
}

/// Write arbitrary length of data to flash, starting at `offset`, from `buf`.
/// Returns Ok(()) on success, or Err(ErrorCode) on failure.
pub fn flash_write(driver: &EmulatedFlashCtrl, offset: usize, buf: &[u8]) -> Result<(), ErrorCode> {
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
            driver.read_page(page_number, &mut tmp)?;
            tmp
        } else {
            EmulatedFlashPage::default()
        };

        page_buf.0[page_offset..page_offset + to_write]
            .copy_from_slice(&buf[buf_offset..buf_offset + to_write]);

        driver.write_page(page_number, &mut page_buf)?;

        remaining -= to_write;
        buf_offset += to_write;
        flash_offset += to_write;
    }
    Ok(())
}

/// Erase arbitrary length of data in flash, starting at `offset`, for `len` bytes.
/// Returns Ok(()) on success, or Err(ErrorCode) on failure.
pub fn flash_erase(driver: &EmulatedFlashCtrl, offset: usize, len: usize) -> Result<(), ErrorCode> {
    if len == 0 {
        return Ok(());
    }
    let start_page = offset / PAGE_SIZE;
    let end_page = (offset + len - 1) / PAGE_SIZE;

    for page in start_page..=end_page {
        driver.erase_page(page)?;
    }
    Ok(())
}
