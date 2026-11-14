// Licensed under the Apache-2.0 license

//! One-time boot scratch borrowed from the idle MCTP responder pool.
//!
//! Certificate-store boot uses the pool before moving ownership into the
//! responder task.

use caliptra_mcu_scratch_alloc::{BitmapAllocator, BITMAP_SLOT_SIZE};
use core::ops::Deref;
use core::ptr::NonNull;

/// Borrowed task scratch that is zeroed when dropped.
pub(crate) struct BootScratch {
    allocator: BitmapAllocator,
    base: NonNull<u8>,
    len: usize,
}

impl BootScratch {
    /// Creates boot scratch over `[base, base + len)`.
    ///
    /// # Safety
    ///
    /// The region must be writable, aligned to [`BITMAP_SLOT_SIZE`], and used by
    /// nothing else until the returned scratch is dropped.
    pub(crate) unsafe fn new(base: NonNull<u8>, len: usize) -> Self {
        debug_assert_eq!(base.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);
        Self {
            // SAFETY: the caller grants exclusive use of the aligned region.
            allocator: BitmapAllocator::new(base, len),
            base,
            len,
        }
    }
}

impl Deref for BootScratch {
    type Target = BitmapAllocator;

    fn deref(&self) -> &BitmapAllocator {
        &self.allocator
    }
}

impl Drop for BootScratch {
    fn drop(&mut self) {
        // SAFETY: `self` still owns the region, and no allocation borrowed
        // from it can outlive `self`.
        unsafe { core::ptr::write_bytes(self.base.as_ptr(), 0, self.len) };
    }
}
