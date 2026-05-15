// Licensed under the Apache-2.0 license

#![allow(static_mut_refs)]

extern crate alloc;
use caliptra_mcu_libtock::console::Console;
use caliptra_mcu_libtock::runtime::set_main;
use core::fmt::Write;
use core::mem::MaybeUninit;
use embedded_alloc::Heap;

const HEAP_SIZE: usize = 0x40;
#[global_allocator]
static HEAP: Heap = Heap::empty();

set_main! {main}

pub(crate) struct EmulatorWriter {}
pub(crate) static mut EMULATOR_WRITER: EmulatorWriter = EmulatorWriter {};

impl core::fmt::Write for EmulatorWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            print_to_console(b);
        }
        Ok(())
    }
}

pub fn print_to_console(byte: u8) {
    // Print to this address for emulator output. Note: this MMIO address is
    // emulator-only; FPGA-bound builds of `example-app` must not invoke
    // `caliptra_mcu_romtime::println!`, since the address is unmapped there
    // and forbidden by user-mode PMP.
    unsafe {
        core::ptr::write_volatile(0x1000_1041 as *mut u8, byte);
    }
}

fn main() {
    unsafe {
        #[allow(static_mut_refs)]
        caliptra_mcu_romtime::set_printer(&mut EMULATOR_WRITER);
    }

    // setup the global allocator for futures
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // Safety: HEAP_MEM is a valid array of MaybeUninit, so we can safely initialize it.
    unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }

    let mut console_writer = Console::writer();
    writeln!(console_writer, "Hello world! from main").unwrap();

    caliptra_mcu_libtockasync::start_async(crate::start());
}
