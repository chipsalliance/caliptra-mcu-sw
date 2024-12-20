// Licensed under the Apache-2.0 license

//! Implementation of flash storage logical driver that maps read, write and erase operations of arbitrary length into page-based operations.
//!
//! It splits non-page-aligned IOs into a series of page level reads, writes and erases.
//! While it is handling an IO, it returns `BUSY` to all additional requests.
//!
//! This module is designed to be used on top of any flash and below any user of `flash_driver::hil::FlashStorage` interface.
//!
//! ```plain
//!         flash_driver::hil::FlashStorage
//!                ┌─────────────┐
//!                │             │
//!                │ This module │
//!                │             │
//!                └─────────────┘
//!               hil::flash::Flash
//! ```

use core::cell::Cell;
use core::{cmp, panic};
use kernel::hil;
use kernel::utilities::cells::NumericCellExt;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Idle,
    Read,
    Write,
    Erase,
}

pub struct FlashStorageToPages<'a, F: hil::flash::Flash + 'static> {
    /// The underlying physical flash driver.
    driver: &'a F,
    /// The client that will be notified when the operation is done.
    client: OptionalCell<&'a dyn crate::hil::FlashStorageClient>,
    /// Buffer correctly sized for the underlying flash page size.
    page_buffer: TakeCell<'static, F::Page>,
    /// Current state of this driver.
    state: Cell<State>,
    /// Temporary holding place for the user's buffer.
    buffer: TakeCell<'static, [u8]>,
    /// Absolute address of where the IO operation starts on the flash. This gets updated
    /// as the operation proceeds across pages.
    address: Cell<usize>,
    /// Total length to read, write or erase. This is stored to return it to the
    /// client.
    length: Cell<usize>,
    /// How many bytes are left to read, write or erase.
    remaining_length: Cell<usize>,
    /// Position in the user buffer.
    buffer_index: Cell<usize>,
    /// Flag to indicate if the erase operation is done and write back is pending.
    partial_erase_wb_pending: Cell<bool>,
}

impl<'a, F: hil::flash::Flash> FlashStorageToPages<'a, F> {
    pub fn new(driver: &'a F, buffer: &'static mut F::Page) -> FlashStorageToPages<'a, F> {
        FlashStorageToPages {
            driver,
            client: OptionalCell::empty(),
            page_buffer: TakeCell::new(buffer),
            state: Cell::new(State::Idle),
            buffer: TakeCell::empty(),
            address: Cell::new(0),
            length: Cell::new(0),
            remaining_length: Cell::new(0),
            buffer_index: Cell::new(0),
            partial_erase_wb_pending: Cell::new(false),
        }
    }
}

impl<'a, F: hil::flash::Flash> crate::hil::FlashStorage<'a> for FlashStorageToPages<'a, F> {
    fn set_client(&self, client: &'a dyn crate::hil::FlashStorageClient) {
        self.client.set(client);
    }

    fn read(
        &self,
        buffer: &'static mut [u8],
        address: usize,
        length: usize,
    ) -> Result<(), ErrorCode> {
        if self.state.get() != State::Idle {
            return Err(ErrorCode::BUSY);
        }

        self.page_buffer
            .take()
            .map_or(Err(ErrorCode::RESERVE), move |page_buffer| {
                let page_size = page_buffer.as_mut().len();

                self.state.set(State::Read);
                self.buffer.replace(buffer);
                self.address.set(address);
                self.length.set(length);
                self.remaining_length.set(length);
                self.buffer_index.set(0);

                match self.driver.read_page(address / page_size, page_buffer) {
                    Ok(()) => Ok(()),
                    Err((error_code, page_buffer)) => {
                        self.page_buffer.replace(page_buffer);
                        Err(error_code)
                    }
                }
            })
    }

    fn write(
        &self,
        buffer: &'static mut [u8],
        address: usize,
        length: usize,
    ) -> Result<(), ErrorCode> {
        if self.state.get() != State::Idle {
            return Err(ErrorCode::BUSY);
        }

        self.page_buffer
            .take()
            .map_or(Err(ErrorCode::RESERVE), move |page_buffer| {
                let page_size = page_buffer.as_mut().len();

                self.state.set(State::Write);
                self.length.set(length);

                if address % page_size == 0 && length >= page_size {
                    // This write is aligned to a page and we are writing an entire page.
                    // Copy data into page buffer.
                    page_buffer.as_mut()[..page_size].copy_from_slice(&buffer[..page_size]);

                    self.buffer.replace(buffer);
                    self.address.set(address + page_size);
                    self.remaining_length.set(length - page_size);
                    self.buffer_index.set(page_size);

                    match self.driver.write_page(address / page_size, page_buffer) {
                        Ok(()) => Ok(()),
                        Err((error_code, page_buffer)) => {
                            self.page_buffer.replace(page_buffer);
                            Err(error_code)
                        }
                    }
                } else {
                    // This write is non-page-aligned, so we need to do a read first.
                    self.buffer.replace(buffer);
                    self.address.set(address);
                    self.remaining_length.set(length);
                    self.buffer_index.set(0);

                    match self.driver.read_page(address / page_size, page_buffer) {
                        Ok(()) => Ok(()),
                        Err((error_code, page_buffer)) => {
                            self.page_buffer.replace(page_buffer);
                            Err(error_code)
                        }
                    }
                }
            })
    }

    fn erase(&self, address: usize, length: usize) -> Result<(), ErrorCode> {
        if self.state.get() != State::Idle {
            return Err(ErrorCode::BUSY);
        }

        self.page_buffer
            .take()
            .map_or(Err(ErrorCode::RESERVE), move |page_buffer| {
                let page_size = page_buffer.as_mut().len();

                self.state.set(State::Erase);
                self.length.set(length);

                if address % page_size == 0 && length >= page_size {
                    // This erase is aligned to a page and we are erasing an entire page.
                    self.address.set(address + page_size);
                    self.remaining_length.set(length - page_size);

                    self.page_buffer.replace(page_buffer);

                    self.driver.erase_page(address / page_size)
                } else {
                    // This erase is non-page-aligned, so we need to do a read first.
                    self.address.set(address);
                    self.remaining_length.set(length);

                    match self.driver.read_page(address / page_size, page_buffer) {
                        Ok(()) => Ok(()),
                        Err((error_code, page_buffer)) => {
                            self.page_buffer.replace(page_buffer);
                            Err(error_code)
                        }
                    }
                }
            })
    }
}

impl<F: hil::flash::Flash> hil::flash::Client<F> for FlashStorageToPages<'_, F> {
    fn read_complete(
        &self,
        page_buffer: &'static mut F::Page,
        _result: Result<(), hil::flash::Error>,
    ) {
        match self.state.get() {
            State::Read => {
                if let Some(buffer) = self.buffer.take() {
                    let page_size = page_buffer.as_mut().len();
                    // This will get the offset into the page.
                    let page_index = self.address.get() % page_size;
                    // Length is either the rest of the page or how much have been left.
                    let len = cmp::min(page_size - page_index, self.remaining_length.get());
                    // This is the current position in the user buffer.
                    let buffer_index = self.buffer_index.get();

                    // Copy data read from the page buffer to the user buffer.
                    buffer[buffer_index..(len + buffer_index)]
                        .copy_from_slice(&page_buffer.as_mut()[page_index..(len + page_index)]);

                    // Decide if the operation is done.
                    let new_len = self.remaining_length.get() - len;
                    if new_len == 0 {
                        // Nothing more to do. Put things back and issue callback.
                        self.page_buffer.replace(page_buffer);
                        self.state.set(State::Idle);
                        self.client
                            .map(move |client| client.read_done(buffer, self.length.get()));
                    } else {
                        // More to read.
                        self.buffer.replace(buffer);
                        // Increment all buffer pointers and state.
                        self.remaining_length.subtract(len);
                        self.address.add(len);
                        self.buffer_index.set(buffer_index + len);

                        if let Err((_, page_buffer)) = self
                            .driver
                            .read_page(self.address.get() / page_size, page_buffer)
                        {
                            self.page_buffer.replace(page_buffer);
                        }
                    }
                }
            }
            State::Write => {
                // Read has been done because it is not page aligned on either or both ends.
                if let Some(buffer) = self.buffer.take() {
                    let page_size = page_buffer.as_mut().len();
                    // This will get us our offset into the page.
                    let page_index = self.address.get() % page_size;
                    // Length is either the rest of the page or how much we have left.
                    let len = cmp::min(page_size - page_index, self.remaining_length.get());
                    // Here is where the operation left off in the user buffer.
                    let buffer_index = self.buffer_index.get();
                    // The page that was read and will be written back to.
                    let page_number = self.address.get() / page_size;

                    // Copy data from the user buffer to the page buffer.
                    page_buffer.as_mut()[page_index..(len + page_index)]
                        .copy_from_slice(&buffer[buffer_index..(len + buffer_index)]);

                    // Do the write.
                    self.buffer.replace(buffer);
                    self.remaining_length.subtract(len);
                    self.address.add(len);
                    self.buffer_index.set(buffer_index + len);
                    if let Err((_, page_buffer)) = self.driver.write_page(page_number, page_buffer)
                    {
                        self.page_buffer.replace(page_buffer);
                    }
                }
            }

            State::Erase => {
                // A read was done because the operation is not page aligned on either or both ends.
                // Perform erase after read.
                let page_size = page_buffer.as_mut().len();
                // Which page was read and which is going to be erased
                let page_number = self.address.get() / page_size;

                self.page_buffer.replace(page_buffer);

                // set a flag write_back pending
                self.partial_erase_wb_pending.set(true);
                let _ = self.driver.erase_page(page_number);
            }
            _ => {}
        }
    }

    fn write_complete(
        &self,
        page_buffer: &'static mut F::Page,
        _result: Result<(), hil::flash::Error>,
    ) {
        match self.state.get() {
            State::Write => {
                // After a write, the operation could be done, need to do another write, or need to
                // do a read.
                if let Some(buffer) = self.buffer.take() {
                    let page_size = page_buffer.as_mut().len();

                    if self.remaining_length.get() == 0 {
                        // Done!
                        self.page_buffer.replace(page_buffer);
                        self.state.set(State::Idle);
                        self.client
                            .map(move |client| client.write_done(buffer, self.length.get()));
                    } else if self.remaining_length.get() >= page_size {
                        // Write an entire page.
                        let buffer_index = self.buffer_index.get();
                        let page_number = self.address.get() / page_size;
                        // Copy data into page buffer.
                        page_buffer.as_mut()[..page_size]
                            .copy_from_slice(&buffer[buffer_index..(page_size + buffer_index)]);

                        self.buffer.replace(buffer);
                        self.remaining_length.subtract(page_size);
                        self.address.add(page_size);
                        self.buffer_index.set(buffer_index + page_size);
                        if let Err((_, page_buffer)) =
                            self.driver.write_page(page_number, page_buffer)
                        {
                            self.page_buffer.replace(page_buffer);
                        }
                    } else {
                        // Write a partial page. Do read first.
                        self.buffer.replace(buffer);
                        if let Err((_, page_buffer)) = self
                            .driver
                            .read_page(self.address.get() / page_size, page_buffer)
                        {
                            self.page_buffer.replace(page_buffer);
                        }
                    }
                }
            }

            State::Erase => {
                // After an erase, the operation could be done, need to do another erase, or need to
                // do a read.
                let page_size = page_buffer.as_mut().len();
                if self.remaining_length.get() == 0 {
                    // Done!
                    self.page_buffer.replace(page_buffer);
                    self.state.set(State::Idle);
                    self.client
                        .map(move |client| client.erase_done(self.length.get()));
                } else if self.remaining_length.get() >= page_size {
                    // Erase another page.
                    let page_number = self.address.get() / page_size;

                    self.remaining_length.subtract(page_size);
                    self.address.add(page_size);

                    self.page_buffer.replace(page_buffer);

                    let _ = self.driver.erase_page(page_number);
                } else {
                    // Erase a partial page. Do read first.
                    if let Err((_, page_buffer)) = self
                        .driver
                        .read_page(self.address.get() / page_size, page_buffer)
                    {
                        self.page_buffer.replace(page_buffer);
                    }
                }
            }
            _ => {}
        }
    }

    fn erase_complete(&self, _result: Result<(), hil::flash::Error>) {
        if let Some(page_buffer) = self.page_buffer.take() {
            let page_size = page_buffer.as_mut().len();

            if self.remaining_length.get() == 0 {
                // Done!
                self.page_buffer.replace(page_buffer);
                self.state.set(State::Idle);
                self.client
                    .map(move |client| client.erase_done(self.length.get()));
            } else if self.partial_erase_wb_pending.get() {
                // Write back the page
                let page_index = self.address.get() % page_size;
                // Length is either the rest of the page or how much is left.
                let len = cmp::min(page_size - page_index, self.remaining_length.get());
                // Which page was read and which is going to be written back to.
                let page_number = self.address.get() / page_size;

                self.remaining_length.subtract(len);
                self.address.add(len);

                // Fill the rest of the page buffer with 0xFF.
                page_buffer.as_mut()[page_index..(len + page_index)].fill(0xFF);

                // Perform the write.
                if let Err((_, page_buffer)) = self.driver.write_page(page_number, page_buffer) {
                    self.page_buffer.replace(page_buffer);
                }

                // Clear the flag
                self.partial_erase_wb_pending.set(false);
            } else if self.remaining_length.get() >= page_size {
                // Erase another page
                let page_number = self.address.get() / page_size;

                self.remaining_length.subtract(page_size);
                self.address.add(page_size);

                self.page_buffer.replace(page_buffer);

                let _ = self.driver.erase_page(page_number);
            } else {
                // Erase a partial page. Do read first.
                if let Err((_, page_buffer)) = self
                    .driver
                    .read_page(self.address.get() / page_size, page_buffer)
                {
                    self.page_buffer.replace(page_buffer);
                }
            }
        } else {
            panic!("internal page buffer must have been set for erase operation");
        }
    }
}
