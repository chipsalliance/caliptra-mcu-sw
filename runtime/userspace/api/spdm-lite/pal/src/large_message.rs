// Licensed under the Apache-2.0 license

//! MCU-side persistent large-message storage for SPDM chunking.

use super::*;
use mcu_error::codes::INVARIANT;

impl SpdmPalLargeMessage for McuSpdmPal {
    #[inline]
    fn capacity(&self) -> usize {
        let large_msg = self.large_msg.take();
        let capacity = large_msg.as_ref().map_or(0, |buf| buf.len());
        self.large_msg.set(large_msg);
        capacity
    }

    fn write(&self, offset: usize, data: &[u8]) -> McuResult<()> {
        let mut large_msg = self.large_msg.take();
        let result = (|| {
            let buf = large_msg.as_deref_mut().ok_or(INVARIANT)?;
            let end = offset.checked_add(data.len()).ok_or(INVARIANT)?;
            let dst = buf.get_mut(offset..end).ok_or(INVARIANT)?;
            dst.copy_from_slice(data);
            Ok(())
        })();
        self.large_msg.set(large_msg);
        result
    }

    fn read(&self, offset: usize, out: &mut [u8]) -> McuResult<()> {
        let large_msg = self.large_msg.take();
        let result = (|| {
            let buf = large_msg.as_deref().ok_or(INVARIANT)?;
            let end = offset.checked_add(out.len()).ok_or(INVARIANT)?;
            let src = buf.get(offset..end).ok_or(INVARIANT)?;
            out.copy_from_slice(src);
            Ok(())
        })();
        self.large_msg.set(large_msg);
        result
    }
}
