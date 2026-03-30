// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![allow(static_mut_refs)]

use core::fmt::Write;

#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::{lazy_lock::LazyLock, signal::Signal};
use libtockasync::TockExecutor;
mod image_loader;

#[cfg(target_arch = "riscv32")]
mod riscv;

struct FpgaWriter {}
static mut FPGA_WRITER: FpgaWriter = FpgaWriter {};

impl Write for FpgaWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print_to_console(s);
        Ok(())
    }
}

fn print_to_console(buf: &str) {
    for b in buf.bytes() {
        // Print to this address for FPGA output
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
    if cfg!(feature = "test-do-nothing") {
        #[allow(clippy::empty_loop)]
        loop {}
    }
    // build a fake kernel so that the app will at least start without Tock
    let _kernel = kernel();
    // call the main function
    libtockasync::start_async(start());
}

#[embassy_executor::task]
async fn start() {
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_printer(&mut FPGA_WRITER);
    }
    async_main().await;
}

pub(crate) async fn async_main() {
    let spawner = EXECUTOR.get().spawner();

    // NOTE: On the emulator, the SPDM task is disabled when firmware update
    // features are enabled due to a known hardfault. If firmware update support
    // is added to the FPGA app, a similar guard should be added here.
    spawner
        .spawn(user_app_common::spdm::spdm_task(spawner))
        .unwrap();

    spawner.spawn(image_loader::image_loading_task()).unwrap();

    spawner
        .spawn(user_app_common::mcu_mbox::mcu_mbox_task(spawner))
        .unwrap();

    #[cfg(feature = "test-mcu-mbox-fips-periodic")]
    spawner
        .spawn(mcu_mbox_lib::fips_periodic::fips_periodic_task())
        .unwrap();

    #[cfg(feature = "test-mctp-vdm-cmds")]
    spawner
        .spawn(user_app_common::vdm::vdm_task(spawner))
        .unwrap();

    loop {
        EXECUTOR.get().poll();
    }
}
