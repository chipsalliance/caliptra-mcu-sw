/*++

Licensed under the Apache-2.0 license.

File Name:

    bus.rs

Abstract:

    File contains definition of the Bus trait.

--*/

use std::{rc::Rc, sync::mpsc};

use caliptra_emu_bus::Event;
use emulator_types::{RvAddr, RvData, RvSize};

/// Signal that a trap should be triggered.
pub type Trap = u32;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BusError {
    /// Instruction access exception
    InstrAccessFault,

    /// Load address misaligned exception
    LoadAddrMisaligned,

    /// Load access fault exception
    LoadAccessFault,

    /// Store address misaligned exception
    StoreAddrMisaligned,

    /// Store access fault exception
    StoreAccessFault,
}

impl From<caliptra_emu_bus::BusError> for BusError {
    fn from(value: caliptra_emu_bus::BusError) -> Self {
        match value {
            caliptra_emu_bus::BusError::InstrAccessFault => BusError::InstrAccessFault,
            caliptra_emu_bus::BusError::LoadAddrMisaligned => BusError::LoadAddrMisaligned,
            caliptra_emu_bus::BusError::LoadAccessFault => BusError::LoadAccessFault,
            caliptra_emu_bus::BusError::StoreAddrMisaligned => BusError::StoreAddrMisaligned,
            caliptra_emu_bus::BusError::StoreAccessFault => BusError::StoreAccessFault,
        }
    }
}

/// Represents an abstract memory bus. Used to read and write from RAM and
/// peripheral addresses.
pub trait Bus {
    /// Read data of specified size from given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::LoadAccessFault` or `BusError::LoadAddrMisaligned`
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError>;

    /// Write data of specified size to given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `addr` - Address to write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError>;

    /// This method is used to notify peripherals of the passage of time. The
    /// owner of this bus MAY call this function periodically, or in response to
    /// a previously scheduled timer event.
    fn poll(&mut self) {
        // By default, do nothing
    }

    fn warm_reset(&mut self) {
        // By default, do nothing
    }

    fn update_reset(&mut self) {
        // By default, do nothing
    }

    fn incoming_event(&mut self, _event: Rc<Event>) {
        // By default, do nothing
    }

    fn register_outgoing_events(&mut self, _sender: mpsc::Sender<Event>) {
        // By default, do nothing
    }
}

pub struct BusConverter {
    caliptra_bus: Box<dyn caliptra_emu_bus::Bus>,
}

impl BusConverter {
    pub fn new(caliptra_bus: Box<dyn caliptra_emu_bus::Bus>) -> Self {
        Self { caliptra_bus }
    }
}

impl Bus for BusConverter {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.caliptra_bus
            .read((size as usize).into(), addr as caliptra_emu_types::RvAddr)
            .map_err(|x| x.into())
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.caliptra_bus
            .write(
                (size as usize).into(),
                addr as caliptra_emu_types::RvAddr,
                val,
            )
            .map_err(|x| x.into())
    }
    fn poll(&mut self) {
        self.caliptra_bus.poll();
    }

    fn warm_reset(&mut self) {
        self.caliptra_bus.warm_reset();
    }

    fn update_reset(&mut self) {
        self.caliptra_bus.update_reset();
    }
}
