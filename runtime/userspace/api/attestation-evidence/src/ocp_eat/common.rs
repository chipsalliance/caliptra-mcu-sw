// Licensed under the Apache-2.0 license

use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

pub(crate) const fn cbor_bstr_len(n: usize) -> usize {
    cbor_head_len(n as u64) + n
}

const fn cbor_head_len(n: u64) -> usize {
    if n <= 23 {
        1
    } else if n <= u8::MAX as u64 {
        2
    } else if n <= u16::MAX as u64 {
        3
    } else if n <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

pub(crate) fn write_type_header(out: &mut [u8], major: u8, value: u64) -> McuResult<usize> {
    if value <= 23 {
        *out.get_mut(0).ok_or(INVARIANT)? = (major << 5) | value as u8;
        Ok(1)
    } else if value <= u8::MAX as u64 {
        *out.get_mut(0).ok_or(INVARIANT)? = (major << 5) | 24;
        *out.get_mut(1).ok_or(INVARIANT)? = value as u8;
        Ok(2)
    } else if value <= u16::MAX as u64 {
        *out.get_mut(0).ok_or(INVARIANT)? = (major << 5) | 25;
        out.get_mut(1..3)
            .ok_or(INVARIANT)?
            .copy_from_slice(&(value as u16).to_be_bytes());
        Ok(3)
    } else if value <= u32::MAX as u64 {
        *out.get_mut(0).ok_or(INVARIANT)? = (major << 5) | 26;
        out.get_mut(1..5)
            .ok_or(INVARIANT)?
            .copy_from_slice(&(value as u32).to_be_bytes());
        Ok(5)
    } else {
        *out.get_mut(0).ok_or(INVARIANT)? = (major << 5) | 27;
        out.get_mut(1..9)
            .ok_or(INVARIANT)?
            .copy_from_slice(&value.to_be_bytes());
        Ok(9)
    }
}
