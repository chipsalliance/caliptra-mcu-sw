// Licensed under the Apache-2.0 license

use caliptra_mcu_network_drivers::println;
use core::arch::asm;

pub fn run() {
    println!("NWP exception test: triggering illegal instruction...");

    unsafe {
        asm!("unimp");
    }

    println!("NWP exception test FAIL: should not reach here");
}
