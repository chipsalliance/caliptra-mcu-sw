// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

use core::fmt::Write;

#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::{lazy_lock::LazyLock, signal::Signal};
use libtockasync::TockExecutor;
#[cfg(any(
    feature = "test-firmware-update-streaming",
    feature = "test-firmware-update-flash"
))]
mod firmware_update;
mod image_loader;
mod mcu_mbox;
mod spdm;

#[cfg(target_arch = "riscv32")]
mod riscv;

pub(crate) struct EmulatorExiter {}
pub(crate) static mut EMULATOR_EXITER: EmulatorExiter = EmulatorExiter {};
impl romtime::Exit for EmulatorExiter {
    fn exit(&mut self, code: u32) {
        // Safety: This is a safe memory address to write to for exiting the emulator.
        unsafe {
            // By writing to this address we can exit the emulator.
            core::ptr::write_volatile(0x1000_2000 as *mut u32, code);
        }
    }
}

struct EmulatorWriter {}
static mut EMULATOR_WRITER: EmulatorWriter = EmulatorWriter {};

impl Write for EmulatorWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print_to_console(s);
        Ok(())
    }
}

fn print_to_console(buf: &str) {
    for b in buf.bytes() {
        // Print to this address for emulator output
        unsafe {
            core::ptr::write_volatile(0x1000_1041 as *mut u8, b);
        }
    }
}

pub static EXECUTOR: LazyLock<TockExecutor> = LazyLock::new(TockExecutor::new);

#[cfg(not(target_arch = "riscv32"))]
pub(crate) fn kernel() -> libtock_unittest::fake::Kernel {
    use libtock_unittest::fake;
    let kernel = fake::Kernel::new();
    let console = fake::Console::new();
    kernel.add_driver(&console);
    kernel
}

#[cfg(not(target_arch = "riscv32"))]
fn main() {
    // build a fake kernel so that the app will at least start without Tock
    let _kernel = kernel();
    // call the main function
    libtockasync::start_async(start());
}

#[embassy_executor::task]
async fn start() {
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_exiter(&mut EMULATOR_EXITER);
        #[allow(static_mut_refs)]
        romtime::set_printer(&mut EMULATOR_WRITER);
    }
    async_main().await;
}

pub(crate) async fn async_main() {
    EXECUTOR
        .get()
        .spawner()
        .spawn(spdm::spdm_task(EXECUTOR.get().spawner()))
        .unwrap();

    EXECUTOR
        .get()
        .spawner()
        .spawn(image_loader::image_loading_task())
        .unwrap();

    EXECUTOR
        .get()
        .spawner()
        .spawn(mcu_mbox::mcu_mbox_task())
        .unwrap();

    loop {
        EXECUTOR.get().poll();
    }
}
