/*++

Licensed under the Apache-2.0 license.

File Name:

    caliptra_to_ext_bus.rs

Abstract:

    File contains the CaliptraToExtBus implementation for handling external
    communication via callbacks.

--*/

use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::{rc::Rc, sync::mpsc};

type ReadCallback = Box<dyn Fn(RvSize, RvAddr, &mut u32) -> bool>;
type WriteCallback = Box<dyn Fn(RvSize, RvAddr, RvData) -> bool>;

/// Bus for handling external communication via callbacks
pub struct CaliptraToExtBus {
    read_callback: Option<ReadCallback>,
    write_callback: Option<WriteCallback>,
}

impl CaliptraToExtBus {
    pub fn new() -> Self {
        Self {
            read_callback: None,
            write_callback: None,
        }
    }

    /// Register a read callback
    pub fn set_read_callback<F>(&mut self, callback: F)
    where
        F: Fn(RvSize, RvAddr, &mut u32) -> bool + 'static,
    {
        self.read_callback = Some(Box::new(callback));
    }

    /// Register a write callback
    pub fn set_write_callback<F>(&mut self, callback: F)
    where
        F: Fn(RvSize, RvAddr, RvData) -> bool + 'static,
    {
        self.write_callback = Some(Box::new(callback));
    }

    // Keep this method for backward compatibility but delegate to set_read_callback
    pub fn external_shim_mut(&mut self) -> &mut Self {
        self
    }
}

impl Default for CaliptraToExtBus {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus for CaliptraToExtBus {
    /// Read data of specified size from given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `BusError::LoadAccessFault` - If no callback is registered or callback returns false
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if let Some(callback) = &self.read_callback {
            let mut buffer: u32 = 0;
            if callback(size, addr, &mut buffer) {
                return Ok(buffer);
            } else {
                return Err(BusError::LoadAccessFault);
            }
        }
        Err(BusError::LoadAccessFault)
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
    /// * `BusError::StoreAccessFault` - If no callback is registered or callback returns false
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        if let Some(callback) = &self.write_callback {
            if callback(size, addr, val) {
                return Ok(());
            } else {
                return Err(BusError::StoreAccessFault);
            }
        }
        Err(BusError::StoreAccessFault)
    }

    fn poll(&mut self) {
        // External communication doesn't need polling
    }

    fn warm_reset(&mut self) {
        // External communication doesn't need reset handling
    }

    fn update_reset(&mut self) {
        // External communication doesn't need reset handling
    }

    fn register_outgoing_events(&mut self, _sender: mpsc::Sender<caliptra_emu_bus::Event>) {
        // External communication doesn't need event handling
    }

    fn incoming_event(&mut self, _event: Rc<caliptra_emu_bus::Event>) {
        // External communication doesn't need event handling
    }
}
