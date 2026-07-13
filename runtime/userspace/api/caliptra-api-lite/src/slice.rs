// Licensed under the Apache-2.0 license

use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;

#[inline]
pub(crate) fn checked_slice(src: &[u8], offset: usize, len: usize) -> McuResult<&[u8]> {
    let end = offset.checked_add(len).ok_or(INVARIANT)?;
    src.get(offset..end).ok_or(INVARIANT)
}

#[inline]
pub(crate) fn internal_slice(src: &[u8], offset: usize, len: usize) -> McuResult<&[u8]> {
    let end = offset.checked_add(len).ok_or(INTERNAL_BUG)?;
    src.get(offset..end).ok_or(INTERNAL_BUG)
}

#[inline]
pub(crate) fn checked_slice_mut(src: &mut [u8], offset: usize, len: usize) -> McuResult<&mut [u8]> {
    let end = offset.checked_add(len).ok_or(INVARIANT)?;
    src.get_mut(offset..end).ok_or(INVARIANT)
}

#[inline]
pub(crate) fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    for (dst_byte, src_byte) in dst.iter_mut().zip(src.iter()) {
        *dst_byte = *src_byte;
    }
}
