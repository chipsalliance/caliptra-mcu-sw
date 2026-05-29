// Licensed under the Apache-2.0 license

//! MCU-side persistent large-message storage for SPDM chunking.

use super::*;
use core::slice;
use mcu_error::codes::INVARIANT;

impl SpdmPalLargeMessage for McuSpdmPal {
    #[inline]
    fn large_message_capacity(&self) -> usize {
        self.large_msg_capacity
    }

    fn write_large_message(&self, offset: usize, data: &[u8]) -> McuResult<()> {
        let ptr = self.large_msg_ptr.ok_or(INVARIANT)?;
        let end = offset.checked_add(data.len()).ok_or(INVARIANT)?;
        if end > self.large_msg_capacity {
            return Err(INVARIANT);
        }
        // SAFETY: the responder is single-tasked and `large_msg_ptr`
        // is exclusively owned by this PAL for its full lifetime.
        unsafe {
            let dst = slice::from_raw_parts_mut(ptr.as_ptr().add(offset), data.len());
            dst.copy_from_slice(data);
        }
        Ok(())
    }

    fn large_message(&self, len: usize) -> McuResult<&[u8]> {
        let ptr = self.large_msg_ptr.ok_or(INVARIANT)?;
        if len > self.large_msg_capacity {
            return Err(INVARIANT);
        }
        // SAFETY: see `write_large_message`; this returns a shared
        // borrow of the currently reassembled prefix only.
        Ok(unsafe { slice::from_raw_parts(ptr.as_ptr(), len) })
    }

    fn large_message_mut(&self, len: usize) -> McuResult<&mut [u8]> {
        let ptr = self.large_msg_ptr.ok_or(INVARIANT)?;
        if len > self.large_msg_capacity {
            return Err(INVARIANT);
        }
        // SAFETY: the responder is single-tasked and this mutable borrow is
        // used only within one stack operation; callers must not retain it
        // across another PAL access to the persistent buffer.
        Ok(unsafe { slice::from_raw_parts_mut(ptr.as_ptr(), len) })
    }
}
