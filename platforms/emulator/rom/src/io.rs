// Licensed under the Apache-2.0 license.

use core::ptr::{read_volatile, write_volatile};

pub fn write(buf: &[u8]) {
    for b in buf {
        write_byte(*b);
    }
}

fn write_byte(b: u8) {
    // Print to this address for emulator output
    // Safety: Accesses memory-mapped registers.
    unsafe {
        write_volatile(0x1000_1041 as *mut u8, b);
    }
}

fn _read_byte() -> u8 {
    unsafe { read_volatile(0x1000_1041 as *mut u8) }
}
