// Licensed under the Apache-2.0 license

#![allow(static_mut_refs)]

extern crate alloc;
use caliptra_mcu_libtock::console::Console;
use caliptra_mcu_libtock::runtime::set_main;
#[allow(unused_imports)]
use core::fmt::Write;
use core::mem::MaybeUninit;
use embedded_alloc::Heap;
/// Boot initialization allocates at most one temporary scratch pool at a time:
/// 4 KiB for measurements, then 9 KiB for certificate-store setup. The
/// remaining 1 KiB covers heap metadata and alignment.
const HEAP_SIZE: usize = 10 * 1024;
#[global_allocator]
static HEAP: Heap = Heap::empty();

set_main! {main}

fn main() {
    if cfg!(feature = "test-do-nothing") {
        #[allow(clippy::empty_loop)]
        loop {}
    }
    // setup the global allocator for futures
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // Safety: HEAP_MEM is a valid array of MaybeUninit, so we can safely initialize it.
    unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }

    let mut console_writer = Console::writer();
    crate::log_info!(console_writer, "Hello world! from SPDM main");

    caliptra_mcu_libtockasync::start_async(crate::start());
}
