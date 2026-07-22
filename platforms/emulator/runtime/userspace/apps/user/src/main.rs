// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![allow(static_mut_refs)]

use core::fmt::Write;

use caliptra_mcu_libtockasync::TockExecutor;
#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::{lazy_lock::LazyLock, signal::Signal};

// Re-export the unified logging macros from userlog so
// `crate::log_*!(...)` call sites in this crate resolve. Dev builds write
// console text; release builds emit defmt frames.
#[allow(unused_imports)]
pub use caliptra_mcu_userlog::{log_debug, log_error, log_info, log_trace, log_warn};
#[allow(unused_imports)]
pub(crate) use caliptra_mcu_userlog::{Bytes, Dbg, Hex32};

#[allow(unused_imports)]
pub use caliptra_mcu_libsyscall_caliptra::console_writeln;

mod caliptra_cmd_handler;
#[cfg(any(
    feature = "test-defmt-logging-mailbox",
    feature = "test-defmt-logging-release",
    feature = "test-defmt-logging-vdm"
))]
mod defmt_test;
#[cfg(any(
    feature = "firmware-update",
    feature = "test-firmware-update-streaming"
))]
mod firmware_update;
mod image_loader;
mod mcu_mbox;
mod measurement;
mod soc_image_descriptors {
    include!(concat!(env!("OUT_DIR"), "/soc_image_descriptors.rs"));
}
#[cfg(target_arch = "riscv32")]
mod panic;
#[cfg(feature = "spdm")]
mod spdm;
#[cfg(feature = "mctp-vdm-service")]
mod vdm;

#[cfg(target_arch = "riscv32")]
mod riscv;

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

fn log_spawn_error() {
    #[cfg(target_arch = "riscv32")]
    print_to_console("[spawn error]\n");
}

pub static EXECUTOR: LazyLock<TockExecutor> = LazyLock::new(TockExecutor::new);

#[cfg(not(target_arch = "riscv32"))]
pub(crate) fn kernel() -> caliptra_mcu_libtock_unittest::fake::Kernel {
    use caliptra_mcu_libtock_unittest::fake;
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
    caliptra_mcu_libtockasync::start_async(start());
}

#[embassy_executor::task]
async fn start() {
    unsafe {
        #[allow(static_mut_refs)]
        caliptra_mcu_romtime::set_printer(&mut EMULATOR_WRITER);
    }
    async_main().await;
}

pub(crate) async fn async_main() {
    // Initialize measurement state before spawning any task that could consume
    // it (image loading, firmware update, SPDM/evidence, MCU mailbox).
    let soc_image_load_list = soc_image_descriptors::SOC_IMAGE_LOAD_LIST;
    measurement::boot_init(
        measurement::attestation_manifest_bytes(),
        soc_image_load_list,
    )
    .await;

    #[cfg(any(
        feature = "test-mctp-spdm-attestation",
        feature = "test-mctp-spdm-attestation-tcb",
        feature = "test-mctp-spdm-attestation-mixed"
    ))]
    if image_loader::seed_attestation_measurements(soc_image_load_list)
        .await
        .is_err()
    {
        caliptra_mcu_libsyscall_caliptra::system::System::exit(1);
    }

    #[cfg(feature = "spdm")]
    spdm::spawn_spdm_tasks(&EXECUTOR.get().spawner());

    #[cfg(not(any(
        feature = "test-mctp-spdm-attestation",
        feature = "test-mctp-spdm-attestation-tcb",
        feature = "test-mctp-spdm-attestation-mixed"
    )))]
    EXECUTOR
        .get()
        .spawner()
        .spawn(image_loader::image_loading_task(soc_image_load_list))
        .map_err(|_| log_spawn_error())
        .ok();

    EXECUTOR
        .get()
        .spawner()
        .spawn(mcu_mbox::mcu_mbox_task())
        .map_err(|_| log_spawn_error())
        .ok();

    #[cfg(feature = "test-mcu-mbox-fips-periodic")]
    EXECUTOR
        .get()
        .spawner()
        .spawn(caliptra_mcu_mbox_lib::fips_periodic::fips_periodic_task())
        .map_err(|_| log_spawn_error())
        .ok();

    #[cfg(feature = "mctp-vdm-service")]
    EXECUTOR
        .get()
        .spawner()
        .spawn(vdm::vdm_task())
        .map_err(|_| log_spawn_error())
        .ok();

    // Production userspace defmt logging: drain staged frames to the flash log
    // capsule for host-side decoding. Device-only (defmt's linker section).
    #[cfg(all(feature = "userspace-log", target_arch = "riscv32"))]
    EXECUTOR
        .get()
        .spawner()
        .spawn(caliptra_mcu_userlog::drain_task())
        .map_err(|_| log_spawn_error())
        .ok();

    #[cfg(any(
        feature = "test-defmt-logging-mailbox",
        feature = "test-defmt-logging-release",
        feature = "test-defmt-logging-vdm"
    ))]
    defmt_test::emit_test_frames();

    loop {
        EXECUTOR.get().poll();
    }
}
