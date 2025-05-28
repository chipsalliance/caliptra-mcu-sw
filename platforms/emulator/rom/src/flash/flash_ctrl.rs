// Licensed under the Apache-2.0 license

// Emulated flash controller driver for MCU ROM.

use core::fmt::Write;
use core::ops::{Index, IndexMut};
use registers_generated::main_flash_ctrl::{
    self,
    bits::{CtrlRegwen, FlControl, FlInterruptEnable, FlInterruptState, OpStatus},
    regs::MainFlashCtrl,
};
use romtime::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

#[allow(dead_code)]
pub const MAIN_FLASH_CTRL_BASE: StaticRef<MainFlashCtrl> =
    unsafe { StaticRef::new(main_flash_ctrl::MAIN_FLASH_CTRL_ADDR as *const MainFlashCtrl) };

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum FlashDrvError {
    // Reserved value, for when "no error" / "success" should be
    // encoded in the same numeric representation as FlashDrvError
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

impl From<FlashDrvError> for usize {
    fn from(err: FlashDrvError) -> usize {
        err as usize
    }
}

impl TryFrom<Result<(), FlashDrvError>> for FlashDrvError {
    type Error = ();

    fn try_from(rc: Result<(), FlashDrvError>) -> Result<Self, Self::Error> {
        match rc {
            Ok(()) => Err(()),
            Err(FlashDrvError::FAIL) => Ok(FlashDrvError::FAIL),
            Err(FlashDrvError::BUSY) => Ok(FlashDrvError::BUSY),
            Err(FlashDrvError::ALREADY) => Ok(FlashDrvError::ALREADY),
            Err(FlashDrvError::OFF) => Ok(FlashDrvError::OFF),
            Err(FlashDrvError::RESERVE) => Ok(FlashDrvError::RESERVE),
            Err(FlashDrvError::INVAL) => Ok(FlashDrvError::INVAL),
            Err(FlashDrvError::SIZE) => Ok(FlashDrvError::SIZE),
            Err(FlashDrvError::CANCEL) => Ok(FlashDrvError::CANCEL),
            Err(FlashDrvError::NOMEM) => Ok(FlashDrvError::NOMEM),
            Err(FlashDrvError::NOSUPPORT) => Ok(FlashDrvError::NOSUPPORT),
            Err(FlashDrvError::NODEVICE) => Ok(FlashDrvError::NODEVICE),
            Err(FlashDrvError::UNINSTALLED) => Ok(FlashDrvError::UNINSTALLED),
            Err(FlashDrvError::NOACK) => Ok(FlashDrvError::NOACK),
        }
    }
}

impl From<FlashDrvError> for Result<(), FlashDrvError> {
    fn from(ec: FlashDrvError) -> Self {
        match ec {
            FlashDrvError::FAIL => Err(FlashDrvError::FAIL),
            FlashDrvError::BUSY => Err(FlashDrvError::BUSY),
            FlashDrvError::ALREADY => Err(FlashDrvError::ALREADY),
            FlashDrvError::OFF => Err(FlashDrvError::OFF),
            FlashDrvError::RESERVE => Err(FlashDrvError::RESERVE),
            FlashDrvError::INVAL => Err(FlashDrvError::INVAL),
            FlashDrvError::SIZE => Err(FlashDrvError::SIZE),
            FlashDrvError::CANCEL => Err(FlashDrvError::CANCEL),
            FlashDrvError::NOMEM => Err(FlashDrvError::NOMEM),
            FlashDrvError::NOSUPPORT => Err(FlashDrvError::NOSUPPORT),
            FlashDrvError::NODEVICE => Err(FlashDrvError::NODEVICE),
            FlashDrvError::UNINSTALLED => Err(FlashDrvError::UNINSTALLED),
            FlashDrvError::NOACK => Err(FlashDrvError::NOACK),
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

#[allow(dead_code)]
impl EmulatedFlashCtrl {
    pub fn initialize_flash_ctrl(base: StaticRef<MainFlashCtrl>) -> EmulatedFlashCtrl {
        let ctrl = EmulatedFlashCtrl { registers: base };
        ctrl.init();
        ctrl
    }

    pub fn capacity(&self) -> usize {
        FLASH_MAX_PAGES * PAGE_SIZE
    }

    fn init(&self) {
        self.registers
            .op_status
            .modify(OpStatus::Err::CLEAR + OpStatus::Done::CLEAR);

        self.clear_error_interrupt();
        self.clear_event_interrupt();
    }

    // Read arbitrary length of data from flash, starting at `offset`, into `buf`.
    // Returns Ok(()) on success, or Err(FlashDrvError) on failure.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), FlashDrvError> {
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
    pub fn write(&self, offset: usize, buf: &[u8]) -> Result<(), FlashDrvError> {
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
    pub fn erase(&self, offset: usize, len: usize) -> Result<(), FlashDrvError> {
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
