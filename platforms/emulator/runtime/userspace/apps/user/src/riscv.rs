// Licensed under the Apache-2.0 license

#![allow(static_mut_refs)]

extern crate alloc;
use core::fmt::Write;
use core::mem::MaybeUninit;
use embedded_alloc::Heap;
use libtock::console::Console;
use libtock::runtime::{set_main, stack_size};

const HEAP_SIZE: usize = 0x3000;
#[global_allocator]
static HEAP: Heap = Heap::empty();

stack_size! {0xa000}
set_main! {main}

fn main() {
    // setup the global allocator for futures
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // Safety: HEAP_MEM is a valid array of MaybeUninit, so we can safely initialize it.
    unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }

    let mut console_writer = Console::writer();
    writeln!(console_writer, "Hello world! from SPDM main").unwrap();

    libtockasync::start_async(crate::start());
}
