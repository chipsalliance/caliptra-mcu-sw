// Licensed under the Apache-2.0 license

//! Adapts a reset-retained memory window to the asynchronous flash-storage HIL.
//!
//! The emulator models DOT storage as root-bus RAM that survives MCU resets
//! because its ROM accesses that window directly through `SimpleFlash`.
//! Runtime userspace uses the standard asynchronous flash syscall, so this
//! adapter exposes the same bytes through that HIL and defers completion
//! callbacks to preserve its asynchronous contract.
//!
//! Validation and the actual RAM read, write, or erase finish before the
//! operation returns `Ok`. Only the corresponding completion callback is
//! deferred; no fallible work remains pending in the deferred handler.

use core::cell::Cell;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;

use caliptra_mcu_flash_driver::hil::{FlashStorage, FlashStorageClient};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Read,
    Write,
    Erase,
}

/// One-operation-at-a-time flash view over an exclusively owned memory slice.
pub struct MemoryFlash<'a> {
    memory: Cell<&'static mut [u8]>,
    client: OptionalCell<&'a dyn FlashStorageClient>,
    buffer: TakeCell<'static, [u8]>,
    operation: OptionalCell<Operation>,
    length: Cell<usize>,
    deferred_call: DeferredCall,
}

impl MemoryFlash<'_> {
    pub fn new(memory: &'static mut [u8]) -> Self {
        Self {
            memory: Cell::new(memory),
            client: OptionalCell::empty(),
            buffer: TakeCell::empty(),
            operation: OptionalCell::empty(),
            length: Cell::new(0),
            deferred_call: DeferredCall::new(),
        }
    }

    fn complete_later(&self, operation: Operation, length: usize) {
        self.operation.set(operation);
        self.length.set(length);
        self.deferred_call.set();
    }
}

impl<'a> FlashStorage<'a> for MemoryFlash<'a> {
    fn set_client(&self, client: &'a dyn FlashStorageClient) {
        self.client.set(client);
    }

    fn read(
        &self,
        buffer: &'static mut [u8],
        address: usize,
        length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if self.operation.is_some() {
            return Err((ErrorCode::BUSY, buffer));
        }
        if length > buffer.len() {
            return Err((ErrorCode::SIZE, buffer));
        }
        let memory = self.memory.take();
        let Some(source) = memory.get(address..address.saturating_add(length)) else {
            self.memory.set(memory);
            return Err((ErrorCode::INVAL, buffer));
        };
        buffer[..length].copy_from_slice(source);
        self.memory.set(memory);
        self.buffer.replace(buffer);
        self.complete_later(Operation::Read, length);
        Ok(())
    }

    fn write(
        &self,
        buffer: &'static mut [u8],
        address: usize,
        length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if self.operation.is_some() {
            return Err((ErrorCode::BUSY, buffer));
        }
        if length > buffer.len() {
            return Err((ErrorCode::SIZE, buffer));
        }
        let memory = self.memory.take();
        let Some(destination) = memory.get_mut(address..address.saturating_add(length)) else {
            self.memory.set(memory);
            return Err((ErrorCode::INVAL, buffer));
        };
        destination.copy_from_slice(&buffer[..length]);
        self.memory.set(memory);
        self.buffer.replace(buffer);
        self.complete_later(Operation::Write, length);
        Ok(())
    }

    fn erase(&self, address: usize, length: usize) -> Result<(), ErrorCode> {
        if self.operation.is_some() {
            return Err(ErrorCode::BUSY);
        }
        let memory = self.memory.take();
        let Some(destination) = memory.get_mut(address..address.saturating_add(length)) else {
            self.memory.set(memory);
            return Err(ErrorCode::INVAL);
        };
        destination.fill(0);
        self.memory.set(memory);
        self.complete_later(Operation::Erase, length);
        Ok(())
    }

    fn erase_size(&self) -> usize {
        // The backing store is RAM and both this adapter and ROM's SimpleFlash
        // erase exact byte ranges by filling them with zero.
        1
    }
}

impl DeferredCallClient for MemoryFlash<'_> {
    fn handle_deferred_call(&self) {
        let Some(operation) = self.operation.take() else {
            return;
        };
        // Mark the adapter idle before invoking the client. FlashPartition may
        // start its next queued request from inside this completion callback.
        let length = self.length.get();
        self.client.map(|client| match operation {
            Operation::Read => client.read_done(self.buffer.take().unwrap(), length),
            Operation::Write => client.write_done(self.buffer.take().unwrap(), length),
            Operation::Erase => client.erase_done(length),
        });
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}
