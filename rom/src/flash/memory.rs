// Licensed under the Apache-2.0 license

//! Simple flash storage implementation using memory. Useful for testing and emulation.

use crate::hil::{FlashDrvError, FlashStorage};
use core::{cell::Cell, result::Result};

pub struct SimpleFlash {
    memory: Cell<&'static mut [u8]>,
}

impl SimpleFlash {
    /// Create a new SimpleFlash instance with the provided memory slice.
    pub fn new(memory: &'static mut [u8]) -> Self {
        SimpleFlash {
            memory: Cell::new(memory),
        }
    }
}

impl FlashStorage for SimpleFlash {
    /// Read from the flash storage, filling the provided buffer with data
    fn read(&self, buffer: &mut [u8], address: usize) -> Result<(), FlashDrvError> {
        let mem = self.memory.take();
        let result = match mem.get(address..address + buffer.len()) {
            Some(slice) if buffer.len() == slice.len() => {
                // SAFETY: This is the same as copy_from_slice, but for some reason
                // the Rust compiler is not optimizing out the panic if the lengths
                // match, even though the lengths always match.
                // Possibly a compiler bug?
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        slice.as_ptr(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                    );
                }
                Ok(())
            }
            _ => Err(FlashDrvError::INVAL),
        };
        self.memory.set(mem);
        result
    }

    /// Write to the flash storage with the full contents of the buffer, starting at the specified address
    fn write(&self, buffer: &[u8], address: usize) -> Result<(), FlashDrvError> {
        let mem = self.memory.take();
        let result = match mem.get_mut(address..address + buffer.len()) {
            Some(slice) if slice.len() == buffer.len() => {
                // SAFETY: This is the same as copy_from_slice, but for some reason
                // the Rust compiler is not optimizing out the panic if the lengths
                // match, even though the lengths always match.
                // Possibly a compiler bug?
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buffer.as_ptr(),
                        slice.as_mut_ptr(),
                        buffer.len(),
                    );
                }
                Ok(())
            }
            _ => Err(FlashDrvError::INVAL),
        };
        self.memory.set(mem);
        result
    }

    /// Erase `length` bytes starting at address `address`. The address must be
    /// in the address space of the physical storage.
    fn erase(&self, address: usize, length: usize) -> Result<(), FlashDrvError> {
        let mem = self.memory.take();
        let result = match mem.get_mut(address..address + length) {
            Some(slice) => {
                slice.fill(0);
                Ok(())
            }
            _ => Err(FlashDrvError::INVAL),
        };
        self.memory.set(mem);
        result
    }

    /// Returns the size of the flash storage in bytes.
    fn capacity(&self) -> usize {
        let mem = self.memory.take();
        let len = mem.len();
        self.memory.set(mem);
        len
    }
}
