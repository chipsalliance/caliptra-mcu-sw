// Licensed under the Apache-2.0 license

//! Imaginary Flash controller driver implementation for FPGA platforms using the MCU mailbox protocol.

#![cfg_attr(target_arch = "riscv32", no_std)]

use core::cell::Cell;
use core::ops::{Index, IndexMut};
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::ErrorCode;
use registers_generated::mci;
use registers_generated::mci::bits::{MboxExecute, MboxTargetStatus};
use romtime::StaticRef;

pub const PAGE_SIZE: usize = 256;
pub const FLASH_MAX_PAGES: usize = 64 * 1024 * 1024 / PAGE_SIZE;
const SOC_RECEIVER_AXI_USER: u32 = 1;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FlashOperation {
    ReadPage = 1,
    WritePage = 2,
    ErasePage = 3,
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
    pub registers: StaticRef<mci::regs::Mci>,
    flash_client: OptionalCell<&'a dyn hil::flash::Client<EmulatedFlashCtrl<'a>>>,
    read_buf: TakeCell<'static, EmulatedFlashPage>,
    write_buf: TakeCell<'static, EmulatedFlashPage>,
    pending_op: OptionalCell<FlashOperation>,
    deferred_call: DeferredCall,
    mailbox_locked: Cell<bool>,
}

impl<'a> EmulatedFlashCtrl<'a> {
    pub fn new(registers: StaticRef<mci::regs::Mci>) -> EmulatedFlashCtrl<'a> {
        EmulatedFlashCtrl {
            registers,
            flash_client: OptionalCell::empty(),
            read_buf: TakeCell::empty(),
            write_buf: TakeCell::empty(),
            pending_op: OptionalCell::empty(),
            deferred_call: DeferredCall::new(),
            mailbox_locked: Cell::new(false),
        }
    }

    pub fn init(&self) {
        self.reset_before_use();
    }

    fn reset_before_use(&self) {
        let mbox_sram_size = (self.registers.mcu_mbox0_csr_mbox_sram.len() * 4) as u32;
        self.registers.mcu_mbox0_csr_mbox_lock.get();
        self.registers.mcu_mbox0_csr_mbox_dlen.set(mbox_sram_size);
        self.registers.mcu_mbox0_csr_mbox_execute.set(0);
    }

    fn acquire_lock(&self) -> Result<(), ErrorCode> {
        if self.registers.mcu_mbox0_csr_mbox_lock.get() != 0 {
            return Err(ErrorCode::BUSY);
        }
        Ok(())
    }

    fn release_lock(&self) {
        self.registers
            .mcu_mbox0_csr_mbox_execute
            .modify(MboxExecute::Execute::CLEAR);
    }

    // Initiate a flash controller IO operation via MCU mailbox.
    // The protocol is as below:
    // Registers:
    //   mbox_cmd  = operation (read/write/erase)
    //   mbox_dlen = total data length (in bytes)
    //   MCU Mailbox SRAM layout:
    //   [0] = page_number
    //   [1] = page_size
    //   [2..] = page data (only for write operations)
    fn submit_io(&self, op: FlashOperation, page_number: usize) -> Result<(), ErrorCode> {
        self.acquire_lock()?;
        self.mailbox_locked.set(true);
        self.pending_op.set(op);

        self.registers.mcu_mbox0_csr_mbox_sram[0].set(page_number as u32);
        self.registers.mcu_mbox0_csr_mbox_sram[1].set(PAGE_SIZE as u32);
        // For write operation, copy the data into MCU MBOX SRAM
        if op == FlashOperation::WritePage {
            if self.write_buf.is_none() {
                self.release_lock();
                self.mailbox_locked.set(false);
                self.pending_op.clear();
                romtime::println!("FLASH_CTRL_DRIVER: WritePage operation requires a buffer");
                return Err(ErrorCode::INVAL);
            }
            let data = self.write_buf.take().unwrap();
            for (i, v) in data.0.chunks(4).enumerate() {
                let mut word: u32 = 0;
                for (j, b) in v.iter().enumerate() {
                    word |= (*b as u32) << (j * 8);
                }
                self.registers.mcu_mbox0_csr_mbox_sram[2 + i].set(word);
            }

            // Put back the write_buf
            self.write_buf.replace(data);
        }

        let total_dlen: u32 = match op {
            FlashOperation::WritePage => (4 + 4 + PAGE_SIZE) as u32,
            _ => 8,
        };

        self.registers.mcu_mbox0_csr_mbox_dlen.set(total_dlen);
        self.registers.mcu_mbox0_csr_mbox_cmd.set(op as u32);
        self.registers
            .mcu_mbox0_csr_mbox_target_user
            .set(SOC_RECEIVER_AXI_USER);
        self.registers.mcu_mbox0_csr_mbox_target_user_valid.set(1);

        self.registers
            .mcu_mbox0_csr_mbox_execute
            .modify(MboxExecute::Execute::SET);

        self.deferred_call.set();
        Ok(())
    }

    fn handle_io_completion(&self) {
        if !self.mailbox_locked.get() || self.pending_op.is_none() {
            return;
        }
        // Check DONE flag in mbox_target_status
        let target_status = self.registers.mcu_mbox0_csr_mbox_target_status.get();
        let done = target_status & MboxTargetStatus::Done::SET.value;
        let status = target_status & MboxTargetStatus::Status::SET.value;

        if done == MboxTargetStatus::Done::SET.value {
            // Operation is complete
            let op = match self.pending_op.take() {
                Some(o) => o,
                None => {
                    panic!("FLASH_CTRL_DRIVER: pending_op is None when target_done is set");
                }
            };

            match op {
                FlashOperation::ReadPage => {
                    let buf = match self.read_buf.take() {
                        Some(b) => b,
                        None => {
                            panic!("FLASH_CTRL_DRIVER: read_buf is not present during ReadPage completion");
                        }
                    };
                    // Get the data len from dlen register
                    let dlen = self.registers.mcu_mbox0_csr_mbox_dlen.get() as usize;
                    if dlen != PAGE_SIZE {
                        self.release_lock();
                        self.mailbox_locked.set(false);
                        self.flash_client.map(|client| {
                            client.read_complete(buf, Err(hil::flash::Error::FlashError));
                        });
                        return;
                    }

                    // Copy read data out of SRAM (starts at sram[0]) into read_buf
                    for i in 0..(PAGE_SIZE / 4) {
                        let word = self.registers.mcu_mbox0_csr_mbox_sram[i].get();
                        buf[i * 4] = (word & 0xff) as u8;
                        buf[i * 4 + 1] = ((word >> 8) & 0xff) as u8;
                        buf[i * 4 + 2] = ((word >> 16) & 0xff) as u8;
                        buf[i * 4 + 3] = ((word >> 24) & 0xff) as u8;
                    }

                    // Release mailbox before invoking client callback because it is possible to
                    // start another IO operation in the callback.
                    self.release_lock();
                    self.mailbox_locked.set(false);

                    self.flash_client.map(|client| {
                        if status == MboxTargetStatus::Status::CmdComplete.value {
                            client.read_complete(buf, Ok(()));
                        } else {
                            client.read_complete(buf, Err(hil::flash::Error::FlashError));
                        }
                    });
                }
                FlashOperation::WritePage => {
                    let buf = match self.write_buf.take() {
                        Some(b) => b,
                        None => {
                            panic!("FLASH_CTRL_DRIVER: write_buf is not present during ReadPage completion");
                        }
                    };
                    self.release_lock();
                    self.mailbox_locked.set(false);
                    self.flash_client.map(|client| {
                        if status == MboxTargetStatus::Status::CmdComplete.value {
                            client.write_complete(buf, Ok(()));
                        } else {
                            client.write_complete(buf, Err(hil::flash::Error::FlashError));
                        }
                    });
                }
                FlashOperation::ErasePage => {
                    self.release_lock();
                    self.mailbox_locked.set(false);

                    self.flash_client.map(|client| {
                        if status == MboxTargetStatus::Status::CmdComplete.value {
                            client.erase_complete(Ok(()));
                        } else {
                            client.erase_complete(Err(hil::flash::Error::FlashError));
                        }
                    });
                }
            }
        } else {
            self.deferred_call.set();
        }
    }
}

impl DeferredCallClient for EmulatedFlashCtrl<'_> {
    fn register(&'static self) {
        self.deferred_call.register(self);
    }

    fn handle_deferred_call(&self) {
        self.handle_io_completion();
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
        if page_number >= FLASH_MAX_PAGES {
            return Err((ErrorCode::INVAL, buf));
        }

        if self.pending_op.is_some() || self.mailbox_locked.get() {
            return Err((ErrorCode::BUSY, buf));
        }

        // Save the buffer
        self.read_buf.replace(buf);

        self.submit_io(FlashOperation::ReadPage, page_number)
            .map_err(|e| (e, self.read_buf.take().unwrap()))
    }

    fn write_page(
        &self,
        page_number: usize,
        buf: &'static mut Self::Page,
    ) -> Result<(), (ErrorCode, &'static mut Self::Page)> {
        if page_number >= FLASH_MAX_PAGES {
            return Err((ErrorCode::INVAL, buf));
        }

        if self.pending_op.is_some() || self.mailbox_locked.get() {
            return Err((ErrorCode::BUSY, buf));
        }

        self.write_buf.replace(buf);
        match self.submit_io(FlashOperation::WritePage, page_number) {
            Ok(()) => Ok(()),
            Err(e) => {
                let buf = self.write_buf.take().unwrap();
                Err((e, buf))
            }
        }
    }

    fn erase_page(&self, page_number: usize) -> Result<(), ErrorCode> {
        if page_number >= FLASH_MAX_PAGES {
            return Err(ErrorCode::INVAL);
        }

        if self.pending_op.is_some() || self.mailbox_locked.get() {
            return Err(ErrorCode::BUSY);
        }

        match self.submit_io(FlashOperation::ErasePage, page_number) {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
