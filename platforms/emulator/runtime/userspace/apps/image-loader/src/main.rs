// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

mod config;

use core::fmt::Write;
#[allow(unused)]
use libsyscall_caliptra::flash::{driver_num, SpiFlash};
use libtock_console::Console;
use libtock_platform::ErrorCode;
use libtockasync::TockExecutor;
#[allow(unused)]
use pldm_lib::daemon::PldmService;

#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::{lazy_lock::LazyLock, signal::Signal};
#[allow(unused)]
use libapi_caliptra::image_loading::{ImageLoader, ImageSource, PldmFirmwareDeviceParams};
use libsyscall_caliptra::DefaultSyscalls;
#[allow(unused)]
use pldm_lib::firmware_device::fd_ops_mock::FdOpsObject;

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

static EXECUTOR: LazyLock<TockExecutor> = LazyLock::new(TockExecutor::new);

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
    }
    async_main().await;
}

pub(crate) async fn async_main() {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "IMAGE_LOADER_APP: Hello async world!").unwrap();
    EXECUTOR
        .get()
        .spawner()
        .spawn(image_loading_task())
        .unwrap();

    loop {
        EXECUTOR.get().poll();
    }
}

#[embassy_executor::task]
async fn image_loading_task() {
    match image_loading().await {
        Ok(_) => romtime::test_exit(0),
        Err(_) => romtime::test_exit(1),
    }
}

pub async fn image_loading() -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "IMAGE_LOADER_APP: Hello async world!").unwrap();
    #[cfg(feature = "test-pldm-streaming-boot")]
    {
        let fw_params = PldmFirmwareDeviceParams {
            descriptors: &config::streaming_boot_consts::DESCRIPTOR.get()[..],
            fw_params: config::streaming_boot_consts::STREAMING_BOOT_FIRMWARE_PARAMS.get(),
        };
        let flash_syscall = SpiFlash::new(driver_num::ACTIVE_IMAGE_PARTITION);
        let pldm_image_loader: ImageLoader = ImageLoader::new(
            ImageSource::Pldm(fw_params),
            flash_syscall,
            EXECUTOR.get().spawner(),
        );
        pldm_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID1)
            .await?;
        pldm_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID2)
            .await?;
        pldm_image_loader.finalize().await?;
    }
    #[cfg(feature = "test-flash-based-boot")]
    {
        let flash_syscall = SpiFlash::new(driver_num::ACTIVE_IMAGE_PARTITION);
        let flash_image_loader: ImageLoader =
            ImageLoader::new(ImageSource::Flash, flash_syscall, EXECUTOR.get().spawner());
        flash_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID1)
            .await?;
        flash_image_loader
            .load_and_authorize(config::streaming_boot_consts::IMAGE_ID2)
            .await?;
        flash_image_loader.finalize().await?;
    }

    #[cfg(any(
        feature = "test-pldm-discovery",
        feature = "test-pldm-fw-update",
        feature = "test-pldm-fw-update-e2e"
    ))]
    {
        let fdops = FdOpsObject::new();
        let mut pldm_service = PldmService::init(&fdops, EXECUTOR.get().spawner());
        writeln!(
            console_writer,
            "PLDM_APP: Starting PLDM service for testing..."
        )
        .unwrap();
        if let Err(e) = pldm_service.start().await {
            writeln!(
                console_writer,
                "PLDM_APP: Error starting PLDM service: {:?}",
                e
            )
            .unwrap();
        }
        // Need to have an await here to let the PLDM service run
        // otherwise it will be stopped immediately
        // and the executor doesn't have a chance to run the tasks
        let suspend_signal: Signal<CriticalSectionRawMutex, ()> = Signal::new();
        suspend_signal.wait().await;
    }
    Ok(())
}
