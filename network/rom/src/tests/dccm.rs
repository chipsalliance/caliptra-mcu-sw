// Licensed under the Apache-2.0 license

use caliptra_mcu_network_drivers::println;
use core::ptr;

pub fn run() {
    println!("NWP DCCM test: starting...");

    // DCCM is at 0x3000_0000, size 64KB (0x10000).
    // BSS/data ends at ~0x3000_01A8; stack floor is ~0x3000_D000.
    // Use a page-aligned address >= 0x3000_1000: the compiler is forced to emit
    // `lui s4, 0x30001` (offset 0x1004 > 2047 rules out lui 0x30000), so the
    // strength-reduced loop's "base - 4" stays in DCCM region (nibble 0x3),
    // avoiding VeeR's region-predication access fault.
    const TEST_BASE: u32 = 0x3000_1000;
    const TEST_WORDS: usize = 16;

    let patterns: [u32; 4] = [0xDEAD_BEEF, 0xCAFE_BABE, 0x1234_5678, 0xA5A5_A5A5];

    for i in 0..TEST_WORDS {
        let addr = (TEST_BASE + (i as u32) * 4) as *mut u32;
        let pattern = patterns[i % patterns.len()];
        unsafe {
            ptr::write_volatile(addr, pattern);
        }
    }

    let mut pass = true;
    for i in 0..TEST_WORDS {
        let addr = (TEST_BASE + (i as u32) * 4) as *const u32;
        let expected = patterns[i % patterns.len()];
        let actual = unsafe { ptr::read_volatile(addr) };
        if actual != expected {
            println!("NWP DCCM FAIL: mismatch at offset {}", i * 4);
            pass = false;
        }
    }

    if pass {
        println!("NWP DCCM test PASS");
    } else {
        println!("NWP DCCM test FAIL");
    }
}
