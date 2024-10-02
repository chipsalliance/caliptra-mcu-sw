/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains entry point for bare-metal RISCV program

--*/

#![no_std]
#![no_main]

use core::arch::global_asm;
use core::ptr;

global_asm!(include_str!("start.S"));

const UART0_REG: *mut u8 = 0x2000_1041 as *mut u8;
const MTIMECMP_REG_LOW: *mut u32 = 0x0200_4000 as *mut u32;
const MTIMECMP_REG_HIGH: *mut u32 = 0x0200_4004 as *mut u32;
const MTIME_REG_LOW: *mut u32 = 0x0200_bff8 as *mut u32;
const MTIME_REG_HIGH: *mut u32 = 0x0200_bffc as *mut u32;
const MTIME_FREQ: u64 = 32768;

fn mtime() -> u64 {
    let mut time: u64;
    unsafe {
        time = ptr::read_volatile(MTIME_REG_HIGH) as u64;
        time <<= 32;
        time |= ptr::read_volatile(MTIME_REG_LOW) as u64;
    }
    time
}

fn set_mtimecmp(x: u64) {
    unsafe {
        ptr::write_volatile(MTIMECMP_REG_LOW, 0xffff_ffff); // ensure that we don't accidentally trigger the timer
        ptr::write_volatile(MTIMECMP_REG_HIGH, (x >> 32) as u32);
        ptr::write_volatile(MTIMECMP_REG_LOW, x as u32);
    }
}

fn mip() -> u32 {
    let mut r: u32;
    unsafe {
        core::arch::asm!("csrr {r}, 0x344",
            r = out(reg) r,
        );
    }
    r
}

fn enable_interrupt(bit: u8) -> u32 {
    let mut r: u32;
    unsafe {
        core::arch::asm!("csrrs {r}, 0x304, {bit}",
            r = out(reg) r,
            bit = in(reg) (1<<bit),
        );
    }
    r
}

fn write_byte(b: u8) {
    unsafe {
        ptr::write_volatile(UART0_REG, b);
    }
}

fn writeln(s: &[u8]) {
    write(s);
    write_byte(b'\n');
}

fn write(s: &[u8]) {
    for byte in s {
        write_byte(*byte);
    }
}

fn write_num(mut n: u64) {
    if n == 0 {
        write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n != 0 {
        buf[i] = (n % 10) as u8 + b'0';
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        write_byte(buf[i]);
    }
}

#[no_mangle]
pub extern "C" fn main() {
    let now = mtime();
    enable_interrupt(7);
    write(b"Starting timer at ");
    write_num(now);
    writeln(b"");
    // set timer for 1ms in the future
    let expected = now + MTIME_FREQ;
    set_mtimecmp(expected);
    while mip() & (1 << 7) == 0 {
        if mtime() % 10000 == 0 {
            writeln(b"Waiting for timer interrupt still");
            write(b"Expected at time ");
            write_num(expected);
            write(b" but now is ");
            write_num(mtime());
            writeln(b"");
        }
    }
    let now = mtime();
    writeln(b"Timer fired at ");
    write_num(now);
    writeln(b"");
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
