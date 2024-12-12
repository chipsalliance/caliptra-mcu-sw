// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Map arbitrary flash storage read, write, and erase operations to page-based operations.

use core::cell::Cell;
use core::{cmp, panic};
use kernel::hil;
use kernel::utilities::cells::NumericCellExt;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;

/// This module is either waiting to do something, or handling a read/write/erase
#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Idle,
    Read,
    Write,
    Erase,
}

pub struct FlashStorageToPages<'a, F: hil::flash::Flash + 'static> {
    /// The module providing a `Flash` interface.
    driver: &'a F,
    /// Callback to the user of this capsule.
    client: OptionalCell<&'a dyn crate::hil::FlashStorageClient>,
    /// Buffer correctly sized for the underlying flash page size.
    page_buffer: TakeCell<'static, F::Page>,
    /// Current state of this capsule.
    state: Cell<State>,
    /// Temporary holding place for the user's buffer.
    buffer: TakeCell<'static, [u8]>,
    /// Absolute address of where we are reading or writing or erasing. This gets updated
    /// as the operation proceeds across pages.
    address: Cell<usize>,
    /// Total length to read, write or erase. We need to store this to return it to the
    /// client.
    length: Cell<usize>,
    /// How many bytes are left to read or write.
    remaining_length: Cell<usize>,
    /// Where we are in the user buffer.
    buffer_index: Cell<usize>,
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

                // Just start reading. We'll worry about how much of the page we
                // want later.
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
                    // This write is aligned to a page and we are writing an entire
                    // page or more.

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
                    // Need to do a read first.
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
                    // This erase is aligned to a page and we are erasing an entire
                    // page or more.
                    self.address.set(address + page_size);
                    self.remaining_length.set(length - page_size);

                    match self.driver.erase_page(address / page_size) {
                        Ok(()) => Ok(()),
                        Err(error_code) => {
                            self.page_buffer.replace(page_buffer);
                            Err(error_code)
                        }
                    }
                } else {
                    // Need to do a read first.
                    self.address.set(address);

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

// Use case:
//  FlashStorageToPages ->  FlashUser -> Mux -> FlashCtrl

// Callback client:
//  FlashCtrl -> Mux -> FlashUser -> FlashStorageToPages
impl<F: hil::flash::Flash> hil::flash::Client<F> for FlashStorageToPages<'_, F> {
    fn read_complete(
        &self,
        page_buffer: &'static mut F::Page,
        _result: Result<(), hil::flash::Error>,
    ) {
        match self.state.get() {
            State::Read => {
                // OK we got a page from flash. Copy what we actually want from it
                // out of it.
                self.buffer.take().map(move |buffer| {
                    let page_size = page_buffer.as_mut().len();
                    // This will get us our offset into the page.
                    let page_index = self.address.get() % page_size;
                    // Length is either the rest of the page or how much we have left.
                    let len = cmp::min(page_size - page_index, self.remaining_length.get());
                    // And where we left off in the user buffer.
                    let buffer_index = self.buffer_index.get();

                    // Copy what we read from the page buffer to the user buffer.
                    buffer[buffer_index..(len + buffer_index)]
                        .copy_from_slice(&page_buffer.as_mut()[page_index..(len + page_index)]);

                    // Decide if we are done.
                    let new_len = self.remaining_length.get() - len;
                    if new_len == 0 {
                        // Nothing more to do. Put things back and issue callback.
                        self.page_buffer.replace(page_buffer);
                        self.state.set(State::Idle);
                        self.client
                            .map(move |client| client.read_done(buffer, self.length.get()));
                    } else {
                        // More to do!
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
                });
            }
            State::Write => {
                // We did a read because we're not page aligned on either or
                // both ends.
                self.buffer.take().map(move |buffer| {
                    let page_size = page_buffer.as_mut().len();
                    // This will get us our offset into the page.
                    let page_index = self.address.get() % page_size;
                    // Length is either the rest of the page or how much we have left.
                    let len = cmp::min(page_size - page_index, self.remaining_length.get());
                    // And where we left off in the user buffer.
                    let buffer_index = self.buffer_index.get();
                    // Which page we read and which we are going to write back to.
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
                });
            }

            State::Erase => {
                // We did a read because we're not page aligned on either or
                // both ends.
               {
                    let page_size = page_buffer.as_mut().len();
                    // This will get us our offset into the page.
                    let page_index = self.address.get() % page_size;
                    // Length is either the rest of the page or how much we have left.
                    let len = cmp::min(page_size - page_index, self.remaining_length.get());

                    // Which page we read and which we are going to write back to.
                    let page_number = self.address.get() / page_size;

                    self.remaining_length.subtract(len);
                    self.address.add(len);

                    // Fill the page buffer from page_index with 0xFF
                    page_buffer.as_mut()[page_index..(len + page_index)].fill(0xFF);

                    // Do the write.
                    if let Err((_, page_buffer)) = self.driver.write_page(page_number, page_buffer) {
                        self.page_buffer.replace(page_buffer);
                    }
                }
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
                 // After a write we could be done, need to do another write, or need to
                 // do a read.
                self.buffer.take().map(move |buffer| {
                    let page_size = page_buffer.as_mut().len();

                    if self.remaining_length.get() == 0 {
                        // Done!
                        self.page_buffer.replace(page_buffer);
                        self.state.set(State::Idle);
                        self.client
                            .map(move |client| client.write_done(buffer, self.length.get()));
                    } else if self.remaining_length.get() >= page_size {
                        // Write an entire page!
                        let buffer_index = self.buffer_index.get();
                        let page_number = self.address.get() / page_size;

                        // Copy data into page buffer.
                        page_buffer.as_mut()[..page_size]
                            .copy_from_slice(&buffer[buffer_index..(page_size + buffer_index)]);

                        self.buffer.replace(buffer);
                        self.remaining_length.subtract(page_size);
                        self.address.add(page_size);
                        self.buffer_index.set(buffer_index + page_size);
                        if let Err((_, page_buffer)) = self.driver.write_page(page_number, page_buffer) {
                            self.page_buffer.replace(page_buffer);
                        }
                    } else {
                        // Write a partial page!
                        self.buffer.replace(buffer);
                        if let Err((_, page_buffer)) = self
                            .driver
                            .read_page(self.address.get() / page_size, page_buffer)
                        {
                            self.page_buffer.replace(page_buffer);
                        }
                    }
                });
            }

            State::Erase => {
                // After an erase we could be done, need to do another erase, or need to
                // do a read.
                let page_size = page_buffer.as_mut().len();
                if self.remaining_length.get() == 0 {
                    // Done!
                    self.page_buffer.replace(page_buffer);
                    self.state.set(State::Idle);
                    self.client
                        .map(move |client| client.erase_done(self.length.get()));
                } else if self.remaining_length.get() >= page_size {
                    // Erase another page!
                    let page_number = self.address.get() / page_size;

                    self.remaining_length.subtract(page_size);
                    self.address.add(page_size);

                    if let Err(_) = self.driver.erase_page(page_number) {
                        self.page_buffer.replace(page_buffer);
                    }
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
            } else if self.remaining_length.get() >= page_size {
                // Erase another page!
                let page_number = self.address.get() / page_size;

                self.remaining_length.subtract(page_size);
                self.address.add(page_size);

                if let Err(_) = self.driver.erase_page(page_number) {
                    self.page_buffer.replace(page_buffer);
                }
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
            // No page buffer. This is an error.
            panic!("No page buffer in erase_complete");
        }

    }

}
