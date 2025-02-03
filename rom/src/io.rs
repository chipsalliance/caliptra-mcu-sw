// Licensed under the Apache-2.0 license.

// Copyright Tock Contributors 2022.
// Copyright (c) 2024 Antmicro <www.antmicro.com>

use core::fmt::Display;
use core::fmt::Write;
use core::ptr::{read_volatile, write_volatile};

pub fn write(buf: &[u8]) {
    for b in buf {
        write_byte(*b);
    }
}

fn write_byte(b: u8) {
    // Print to this address for emulator output
    // # Safety
    // Accesses memory-mapped registers.
    unsafe {
        write_volatile(0x1000_1041 as *mut u8, b);
    }
}

fn _read_byte() -> u8 {
    unsafe { read_volatile(0x1000_1041 as *mut u8) }
}

pub struct HexBytes<'a>(pub &'a [u8]);
impl Display for HexBytes<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Rust can't prove the indexes are correct in a format macro.
        for &x in self.0.iter() {
            let c = x >> 4;
            if c < 10 {
                f.write_char((c + b'0') as char)?;
            } else {
                f.write_char((c - 10 + b'A') as char)?;
            }
            let c = x & 0xf;
            if c < 10 {
                f.write_char((c + b'0') as char)?;
            } else {
                f.write_char((c - 10 + b'A') as char)?;
            }
        }
        Ok(())
    }
}

pub struct HexWord(pub u32);
impl Display for HexWord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        HexBytes(&self.0.to_be_bytes()).fmt(f)
    }
}
