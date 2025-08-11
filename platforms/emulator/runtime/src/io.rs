// Licensed under the Apache-2.0 license.

// Copyright Tock Contributors 2022.
// Copyright (c) 2024 Antmicro <www.antmicro.com>

#![allow(static_mut_refs)]

use crate::CHIP;
use crate::PROCESSES;
use crate::PROCESS_PRINTER;
use core::cell::Cell;
use core::fmt::Write;
use core::panic::PanicInfo;
use core::ptr::{addr_of, addr_of_mut};
use core::ptr::{read_volatile, write_volatile};
use kernel::debug;
use kernel::debug::IoWrite;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;

pub(crate) static mut WRITER: Writer = Writer {};

/// Panic handler.
///
/// # Safety
/// Accesses memory-mapped registers.
#[cfg(not(test))]
#[no_mangle]
#[panic_handler]
pub unsafe fn panic_fmt(pi: &PanicInfo) -> ! {
    let writer = &mut *addr_of_mut!(WRITER);
    debug::panic_print(
        writer,
        pi,
        &rv32i::support::nop,
        &*addr_of!(PROCESSES),
        &*addr_of!(CHIP),
        &*addr_of!(PROCESS_PRINTER),
    );
    exit_emulator(1);
}

/// Exit the emulator
pub fn exit_emulator(exit_code: u32) -> ! {
    // Safety: This is a safe memory address to write to for exiting the emulator.
    unsafe {
        // By writing to this address we can exit the emulator.
        write_volatile(0x1000_2000 as *mut u32, exit_code);
    }
    unreachable!()
}

pub struct Writer {}

impl Write for Writer {
    fn write_str(&mut self, s: &str) -> ::core::fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

impl IoWrite for Writer {
    fn write(&mut self, buf: &[u8]) -> usize {
        for b in buf {
            // Print to this address for emulator output
            unsafe {
                write_volatile(0x1000_1041 as *mut u8, *b);
            }
        }
        buf.len()
    }
}

fn read_byte() -> u8 {
    unsafe { read_volatile(0x1000_1041 as *mut u8) }
}

pub struct SemihostUart<'a> {
    rx_client: OptionalCell<&'a dyn hil::uart::ReceiveClient>,
    rx_buffer: TakeCell<'static, [u8]>,
    rx_index: Cell<usize>,
    rx_len: Cell<usize>,
    tx_client: OptionalCell<&'a dyn hil::uart::TransmitClient>,
    tx_buffer: TakeCell<'static, [u8]>,
    tx_len: Cell<usize>,
    deferred_call: DeferredCall,
}

impl<'a> SemihostUart<'a> {
    pub fn new() -> SemihostUart<'a> {
        SemihostUart {
            rx_client: OptionalCell::empty(),
            rx_buffer: TakeCell::empty(),
            rx_len: Cell::new(0),
            rx_index: Cell::new(0),
            tx_client: OptionalCell::empty(),
            tx_buffer: TakeCell::empty(),
            tx_len: Cell::new(0),
            deferred_call: DeferredCall::new(),
        }
    }

    pub fn init(&'static self) {}

    pub fn handle_interrupt(&self) {
        let mut b = read_byte();
        while b != 0 {
            if let Some(rx_buffer) = self.rx_buffer.take() {
                let len = self.rx_len.get();
                let mut index = self.rx_index.get();
                if index < len {
                    rx_buffer[index] = b;
                    index += 1;
                }
                if index == len {
                    // send to the client
                    self.rx_client.map(move |client| {
                        client.received_buffer(rx_buffer, len, Ok(()), hil::uart::Error::None)
                    });
                } else {
                    self.rx_index.set(index);
                    self.rx_buffer.replace(rx_buffer);
                }
            }
            b = read_byte();
        }
    }
}

impl<'a> hil::uart::Configure for SemihostUart<'a> {
    fn configure(&self, _params: hil::uart::Parameters) -> Result<(), ErrorCode> {
        Ok(())
    }
}

impl<'a> hil::uart::Transmit<'a> for SemihostUart<'a> {
    fn set_transmit_client(&self, client: &'a dyn hil::uart::TransmitClient) {
        self.tx_client.set(client);
    }

    fn transmit_buffer(
        &self,
        tx_buffer: &'static mut [u8],
        tx_len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if tx_len == 0 || tx_len > tx_buffer.len() {
            Err((ErrorCode::SIZE, tx_buffer))
        } else if self.tx_buffer.is_some() {
            Err((ErrorCode::BUSY, tx_buffer))
        } else {
            unsafe {
                WRITER.write(&tx_buffer[..tx_len]);
            }
            self.tx_len.set(tx_len);
            self.tx_buffer.replace(tx_buffer);
            // The whole buffer was transmitted immediately
            self.deferred_call.set();
            Ok(())
        }
    }

    fn transmit_word(&self, _word: u32) -> Result<(), ErrorCode> {
        Err(ErrorCode::FAIL)
    }

    fn transmit_abort(&self) -> Result<(), ErrorCode> {
        Err(ErrorCode::FAIL)
    }
}

impl<'a> hil::uart::Receive<'a> for SemihostUart<'a> {
    fn set_receive_client(&self, client: &'a dyn hil::uart::ReceiveClient) {
        self.rx_client.set(client);
    }
    fn receive_buffer(
        &self,
        rx_buffer: &'static mut [u8],
        rx_len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        // Ensure the provided buffer holds at least `rx_len` bytes, and
        // `rx_len` is strictly positive (otherwise we'd need to use deferred
        // calls):
        if rx_buffer.len() < rx_len && rx_len > 0 {
            return Err((ErrorCode::SIZE, rx_buffer));
        }

        // Store the receive buffer and byte count. We cannot call into the
        // generic receive routine here, as the client callback needs to be
        // called from another call stack.
        self.rx_buffer.replace(rx_buffer);
        self.rx_len.set(rx_len);
        Ok(())
    }
    fn receive_word(&self) -> Result<(), ErrorCode> {
        Err(ErrorCode::FAIL)
    }
    fn receive_abort(&self) -> Result<(), ErrorCode> {
        Err(ErrorCode::FAIL)
    }
}

impl<'a> DeferredCallClient for SemihostUart<'a> {
    fn register(&'static self) {
        self.deferred_call.register(self);
    }

    fn handle_deferred_call(&self) {
        self.tx_client.map(|client| {
            self.tx_buffer.take().map(|tx_buf| {
                client.transmitted_buffer(tx_buf, self.tx_len.get(), Ok(()));
            });
        });
    }
}
