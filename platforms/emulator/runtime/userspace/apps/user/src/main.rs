// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![allow(static_mut_refs)]

#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::lazy_lock::LazyLock;
use libtockasync::TockExecutor;
#[cfg(any(
    feature = "test-firmware-update-streaming",
    feature = "test-firmware-update-flash"
))]
pub(crate) mod firmware_update;
mod image_loader;

#[cfg(target_arch = "riscv32")]
mod riscv;

pub static EXECUTOR: LazyLock<TockExecutor> = LazyLock::new(TockExecutor::new);

static mut WRITER: user_app_common::MmioWriter = user_app_common::MmioWriter {
    addr: 0x1000_1041 as *mut u8,
};

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
    if cfg!(feature = "test-do-nothing") {
        #[allow(clippy::empty_loop)]
        loop {}
    }
    let _kernel = kernel();
    libtockasync::start_async(start());
}

#[embassy_executor::task]
async fn start() {
    unsafe {
        romtime::set_printer(&mut WRITER);
    }
    user_app_common::async_main(EXECUTOR.get(), |spawner| {
        spawner.spawn(image_loader::image_loading_task()).unwrap();
    })
    .await;
}
