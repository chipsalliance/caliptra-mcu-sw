// Licensed under the Apache-2.0 license

#![allow(static_mut_refs)]

extern crate alloc;
use core::fmt::Write;
use core::mem::MaybeUninit;
use embedded_alloc::Heap;
use libtock::console::Console;
use libtock::runtime::{set_main, stack_size};

const HEAP_SIZE: usize = 0x40;
#[global_allocator]
static HEAP: Heap = Heap::empty();

stack_size! {0x9000}
set_main! {main}

// TODO: remove this dependence on the emulator when the emulator-specific
// pieces are moved to platform/emulator/runtime
pub(crate) struct EmulatorWriter {}
pub(crate) static mut EMULATOR_WRITER: EmulatorWriter = EmulatorWriter {};

impl core::fmt::Write for EmulatorWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print_to_console(s);
        Ok(())
    }
}

pub(crate) fn print_to_console(buf: &str) {
    for b in buf.bytes() {
        // Print to this address for emulator output
        unsafe {
            core::ptr::write_volatile(0x1000_1041 as *mut u8, b);
        }
    }
}

fn main() {
    // TODO: remove this when the emulator-specific pieces are moved to
    // platform/emulator/runtime
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_printer(&mut EMULATOR_WRITER);
    }

    // setup the global allocator for futures
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // Safety: HEAP_MEM is a valid array of MaybeUninit, so we can safely initialize it.
    unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }

    let mut console_writer = Console::writer();
    writeln!(console_writer, "Hello world! from main").unwrap();

    libtockasync::start_async(crate::start());
}
