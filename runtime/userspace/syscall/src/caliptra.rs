// Licensed under the Apache-2.0 license

//! # Caliptra Interface
extern crate alloc;
use crate::DefaultSyscalls;
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use core::marker::PhantomData;

/// Caliptra interface user interface.
///
/// # Generics
/// - `S`: The syscall implementation.
pub struct Caliptra<S: Syscalls = DefaultSyscalls> {
    _syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Default for Caliptra<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> Caliptra<S> {
    pub fn new() -> Self {
        Self {
            _syscall: PhantomData,
            driver_num: CALIPTRA_DRIVER_NUM,
        }
    }

    pub fn read(&self, reg_offset: u32, index: u32) -> Result<u32, ErrorCode> {
        S::command(
            self.driver_num,
            cmd::CALIPTRA_SET_REGISTER,
            reg_offset,
            index,
        )
        .to_result::<(), ErrorCode>()?;

        S::command(self.driver_num, cmd::CALIPTRA_READ, reg_offset, index)
            .to_result::<u32, ErrorCode>()
    }

    /// Reads the vendor PK hash from the Caliptra fuses.
    pub fn read_vendor_pk_hash(&self) -> Result<[u8; 48], ErrorCode> {
        let mut fuse_value = [0u8; 48];
        for (i, chunk) in fuse_value.chunks_exact_mut(4).enumerate() {
            let word = self.read(reg::VENDOR_PK_HASH, i as u32)?;
            let bytes = word.to_le_bytes();
            chunk.copy_from_slice(&bytes);
        }
        Ok(fuse_value)
    }
}

// -----------------------------------------------------------------------------
// Command IDs and Caliptra-specific constants
// -----------------------------------------------------------------------------

// Driver number for the Caliptra interface
pub const CALIPTRA_DRIVER_NUM: u32 = 0x8000_0011;

pub mod cmd {
    pub const CALIPTRA_READ: u32 = 1;
    pub const CALIPTRA_WRITE: u32 = 2;
    pub const CALIPTRA_SET_REGISTER: u32 = 3;
}

pub mod reg {
    pub const VENDOR_PK_HASH: u32 = 0x260;
}
