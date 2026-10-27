/*++

Licensed under the Apache-2.0 license.

File Name:

    emu_ctrl.rs

Abstract:

    File contains emulation control device implementation.

--*/

use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::process::exit;
use std::{cell::Cell, rc::Rc};

/// Emulation Control
pub struct EmuCtrl {
    exit_status: Option<Rc<Cell<Option<i32>>>>,
}

impl EmuCtrl {
    // Exit emulator address
    const ADDR_EXIT: RvAddr = 0x0000_0000;

    /// Create an new instance of emulator control
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the device
    pub fn new() -> Self {
        Self { exit_status: None }
    }
    pub fn capture_exit(&mut self, status: Rc<Cell<Option<i32>>>) {
        self.exit_status = Some(status);
    }
    /// Memory map size.
    pub fn mmap_size(&self) -> RvAddr {
        4
    }
}
impl Default for EmuCtrl {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus for EmuCtrl {
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
            (RvSize::Word, EmuCtrl::ADDR_EXIT) => Ok(0),
            _ => Err(BusError::LoadAccessFault),
        }
    }

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
    /// * `RvException` - Exception with cause `RvExceptionCause::StoreAccessFault`
    ///   or `RvExceptionCause::StoreAddrMisaligned`
    fn write(&mut self, _size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            EmuCtrl::ADDR_EXIT => {
                if let Some(status) = &self.exit_status {
                    eprintln!("MCU requested emulator exit with status {}", val as i32);
                    status.set(Some(val as i32));
                } else {
                    exit(val as i32);
                }
            }

            _ => Err(BusError::StoreAccessFault)?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_guest_exit_without_terminating_host() {
        for code in [0, 1, -1] {
            let status = Rc::new(Cell::new(None));
            let mut ctrl = EmuCtrl::new();
            ctrl.capture_exit(status.clone());
            ctrl.write(RvSize::Word, EmuCtrl::ADDR_EXIT, code as u32)
                .unwrap();
            assert_eq!(status.get(), Some(code));
        }
    }
}
