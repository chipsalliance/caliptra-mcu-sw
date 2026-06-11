// Licensed under the Apache-2.0 license

//! Small CBOR length helpers shared by EAT/COSE code.

pub const fn cbor_bstr_len(n: usize) -> usize {
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
