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
use std::io::Write;
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
        }
    }

    /// Memory map size.
    pub fn mmap_size(&self) -> RvAddr {
        256
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
                Some(output) => write!(output.borrow_mut(), "{}", value as u8 as char).unwrap(),
                None => eprint!("{}", value as u8 as char),
            },
            _ => Err(BusError::StoreAccessFault)?,
        }
        Ok(())
    }
}
