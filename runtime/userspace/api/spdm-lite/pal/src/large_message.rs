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

    fn read_large_message(&self, offset: usize, out: &mut [u8]) -> McuResult<()> {
        let ptr = self.large_msg_ptr.ok_or(INVARIANT)?;
        let end = offset.checked_add(out.len()).ok_or(INVARIANT)?;
        if end > self.large_msg_capacity {
            return Err(INVARIANT);
        }
        // SAFETY: see `write_large_message`; this only copies out of
        // the currently reassembled range and does not return a borrow.
        unsafe {
            let src = slice::from_raw_parts(ptr.as_ptr().add(offset), out.len());
            out.copy_from_slice(src);
        }
        Ok(())
    }
}
