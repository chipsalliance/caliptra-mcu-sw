// Licensed under the Apache-2.0 license.

// Copyright Tock Contributors 2022.
// Copyright (c) 2024 Antmicro <www.antmicro.com>

use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

/// Panic handler.
///
#[cfg(not(test))]
#[no_mangle]
#[panic_handler]
pub fn panic_fmt(_pi: &PanicInfo) -> ! {
    // TODO: use ufmt / caliptra driver
    write(b"Panic!\r\n");

    // Cause the emulator to exit
    unsafe {
        write_volatile(0x1000_2000 as *mut u32, 0);
    }
    unreachable!()
}

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
