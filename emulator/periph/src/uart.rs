/*++

Licensed under the Apache-2.0 license.

File Name:

    uart.rs

Abstract:

    File contains UART device implementation.

--*/

use caliptra_emu_bus::{Bus, BusError, Clock, Timer};
use caliptra_emu_cpu::Irq;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

pub struct Uart {
    bit_rate: u8,
    data_bits: u8,
    stop_bits: u8,
    output: Option<Rc<RefCell<Vec<u8>>>>,
    input: Option<Arc<Mutex<Option<u8>>>>,
    bytes_read: Cell<u64>,
    byte_last_irq_triggered: Cell<u64>,
    irq: Irq,
    timer: Timer,
    char_buffer: Cell<PartialUtf8>,
}

impl Uart {
    /// Bit Rate Register
    const ADDR_BIT_RATE: RvAddr = 0x00000010;

    /// Data Bits Register
    const ADDR_DATA_BITS: RvAddr = 0x00000011;

    /// Stop Bits Register
    const ADDR_STOP_BITS: RvAddr = 0x00000012;

    /// Transmit status Register
    const ADDR_TX_STATUS: RvAddr = 0x00000040;

    /// Transmit Data Register
    const ADDR_TX_DATA: RvAddr = 0x00000041;

    pub fn new(
        output: Option<Rc<RefCell<Vec<u8>>>>,
        input: Option<Arc<Mutex<Option<u8>>>>,
        irq: Irq,
        clock: &Clock,
    ) -> Self {
        Self {
            bit_rate: 0,
            data_bits: 8,
            stop_bits: 1,
            output,
            input,
            irq,
            bytes_read: Cell::new(0),
            byte_last_irq_triggered: Cell::new(u64::MAX),
            timer: Timer::new(clock),
            char_buffer: Cell::new(PartialUtf8::new()),
        }
    }
}

impl Bus for Uart {
    fn poll(&mut self) {
        // if we have input waiting, then trigger an interrupt if we haven't already
        if let Some(input) = self.input.as_ref() {
            if input.lock().unwrap().is_some() {
                if self.byte_last_irq_triggered.get() != self.bytes_read.get() {
                    self.byte_last_irq_triggered.set(self.bytes_read.get());
                    self.irq.set_level(true);
                    self.timer.schedule_poll_in(1); // make sure that the interrupt is triggered
                }
            } else {
                // clear the interrupt
                self.irq.set_level(false);
            }
        }
    }

    /// Read data of specified size from given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::LoadAccessFault`
    ///   or `RvExceptionCause::LoadAddrMisaligned`
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        match (size, addr) {
            (RvSize::Byte, Uart::ADDR_BIT_RATE) => Ok(self.bit_rate as RvData),
            (RvSize::Byte, Uart::ADDR_DATA_BITS) => Ok(self.data_bits as RvData),
            (RvSize::Byte, Uart::ADDR_STOP_BITS) => Ok(self.stop_bits as RvData),
            (RvSize::Byte, Uart::ADDR_TX_STATUS) => Ok(1),
            (RvSize::Byte, Uart::ADDR_TX_DATA) => match &self.input {
                Some(input) => {
                    let mut input = input.lock().unwrap();
                    match input.take() {
                        Some(data) => {
                            self.bytes_read.set(self.bytes_read.get() + 1);
                            Ok(data as RvData)
                        }
                        None => Ok(0),
                    }
                }
                None => Ok(0),
            },
            _ => Err(BusError::LoadAccessFault),
        }
    }

    /// Write data of specified size to given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `addr` - Address to write
    /// * `data` - Data to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::StoreAccessFault`
    ///   or `RvExceptionCause::StoreAddrMisaligned`
    fn write(&mut self, size: RvSize, addr: RvAddr, value: RvData) -> Result<(), BusError> {
        match (size, addr) {
            (RvSize::Byte, Uart::ADDR_BIT_RATE) => self.bit_rate = value as u8,
            (RvSize::Byte, Uart::ADDR_DATA_BITS) => self.data_bits = value as u8,
            (RvSize::Byte, Uart::ADDR_STOP_BITS) => self.stop_bits = value as u8,
            (RvSize::Byte, Uart::ADDR_TX_DATA) => match &self.output {
                Some(output) => {
                    let mut out = output.borrow_mut();
                    out.push(value as u8);
                }
                None => {
                    match value as u8 {
                        // normal ASCII
                        0x02..=0x7f => eprint!("{}", value as u8 as char),
                        // UTF-8 multi-byte sequences
                        0x80..=0xf4 => {
                            let mut partial = self.char_buffer.take();
                            partial.push(value as u8);
                            while let Some(c) = partial.next() {
                                eprint!("{}", c);
                            }
                            self.char_buffer.set(partial);
                        }
                        _ => (), // ignore test result characters
                    }
                }
            },
            _ => Err(BusError::StoreAccessFault)?,
        }
        Ok(())
    }
}

/// Buffers up to 4 bytes to interpret as UTF-8 characters.
/// If 4 bytes are buffered and no valid character can be formed,
/// then the first byte is returned as a literal (invalid) character
/// and the rest are shifted down.
#[derive(Clone, Copy)]
struct PartialUtf8 {
    len: usize,
    buf: [u8; 4],
}

impl Default for PartialUtf8 {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialUtf8 {
    fn new() -> Self {
        Self {
            len: 0,
            buf: [0; 4],
        }
    }

    fn push(&mut self, ch: u8) {
        self.buf[self.len] = ch;
        self.len += 1;
    }

    fn next(&mut self) -> Option<char> {
        if self.len == 0 {
            return None;
        }
        // check partial sequences
        for l in 1..=self.len {
            let v = &self.buf[..l];
            // avoid extra borrow
            let ch = match std::str::from_utf8(v) {
                Ok(s) => s.chars().next(),
                _ => None,
            };
            if let Some(ch) = ch {
                self.buf.copy_within(l..4, 0);
                self.len -= l;
                return Some(ch);
            }
        }
        if self.len == 4 {
            // Invalid UTF-8 sequence, just output one character and shift the rest down
            let ch = self.buf[0] as char;
            self.buf.copy_within(1..4, 0);
            self.len -= 1;
            Some(ch)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_utf8_buffer() {
        let mut p = PartialUtf8::new();
        p.push(0x20);
        assert!(p.next() == Some(' '));
        assert!(p.next().is_none());

        for ch in 0..0x7f {
            // all ASCII characters are single byte
            p.push(ch);
            assert!(p.next() == Some(ch as char));
            assert!(p.next().is_none());
        }

        // 2-byte UTF-8 character
        p.push(0xCE);
        assert_eq!(p.next(), None);
        p.push(0x92);
        assert_eq!(p.next(), Some('Β'));
        assert_eq!(p.next(), None);

        // 3-byte UTF-8 character
        p.push(0xEC);
        assert_eq!(p.next(), None);
        p.push(0x9C);
        assert_eq!(p.next(), None);
        p.push(0x84);
        assert_eq!(p.next(), Some('위'));
        assert_eq!(p.next(), None);

        // 4-byte UTF-8 character
        p.push(0xF0);
        assert_eq!(p.next(), None);
        p.push(0x90);
        assert_eq!(p.next(), None);
        p.push(0x8D);
        assert_eq!(p.next(), None);
        p.push(0x85);
        assert_eq!(p.next(), Some('𐍅'));
        assert_eq!(p.next(), None);

        // invalid UTF-8 sequence
        p.push(0xF0);
        assert_eq!(p.next(), None);
        p.push(0x20);
        assert_eq!(p.next(), None);
        p.push(0x21);
        assert_eq!(p.next(), None);
        p.push(0x22);
        assert_eq!(p.next(), Some(0xF0 as char));
        assert_eq!(p.next(), Some(0x20 as char));
        assert_eq!(p.next(), Some(0x21 as char));
        assert_eq!(p.next(), Some(0x22 as char));
    }
}
