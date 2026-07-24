// Licensed under the Apache-2.0 license

#[cfg(feature = "mcu-mbox-service")]
pub(crate) mod cmd_auth_mock;
#[cfg(feature = "mcu-mbox-test-handlers")]
mod cmd_handler_mock;

use caliptra_mcu_libsyscall_caliptra::system::System;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_platform::ErrorCode;
#[cfg(feature = "mcu-mbox-service")]
use caliptra_mcu_mbox_lib::cmd_interface::McuMboxScratch;
#[cfg(feature = "mcu-mbox-service")]
use caliptra_mcu_spdm_pal::{
    BitmapAllocator, BitmapBytes, StaticBitmapAllocatorCell, BITMAP_SLOT_SIZE,
};
#[allow(unused_imports)]
use core::fmt::Write;
#[cfg(feature = "mcu-mbox-service")]
use core::ptr::NonNull;
#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::signal::Signal;

#[cfg(feature = "mcu-mbox-service")]
const MCU_MBOX_SCRATCH_SIZE: usize = 12 * 1024;

#[cfg(feature = "mcu-mbox-service")]
struct McuMboxScratchAlloc(&'static BitmapAllocator);

#[cfg(feature = "mcu-mbox-service")]
impl mcu_caliptra_api_lite::ApiAlloc for McuMboxScratchAlloc {
    type Buf<'a>
        = BitmapBytes<'a>
    where
        Self: 'a;

    fn alloc(&self, len: usize) -> mcu_error::McuResult<Self::Buf<'_>> {
        self.0.alloc_bytes(len)
    }
}

#[cfg(feature = "mcu-mbox-service")]
impl McuMboxScratch for McuMboxScratchAlloc {
    fn shrink(buf: &mut BitmapBytes<'_>, new_len: usize) -> mcu_error::McuResult<()> {
        buf.shrink(new_len)
    }
}

#[embassy_executor::task]
pub async fn mcu_mbox_task() {
    match start_mcu_mbox_service().await {
        Ok(_) => {}
        Err(_) => System::exit(1),
    }
}

#[allow(dead_code)]
#[allow(unused_variables)]
async fn start_mcu_mbox_service() -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    crate::log_info!(console_writer, "Starting MCU_MBOX task...");

    #[cfg(feature = "mcu-mbox-service")]
    {
        #[repr(C, align(64))]
        struct ScratchBuf([u8; MCU_MBOX_SCRATCH_SIZE]);
        static mut MCU_MBOX_SCRATCH: ScratchBuf = ScratchBuf([0u8; MCU_MBOX_SCRATCH_SIZE]);
        // SAFETY: this task is the sole owner of `MCU_MBOX_SCRATCH`.
        let scratch_ptr: NonNull<u8> =
            unsafe { NonNull::new_unchecked(MCU_MBOX_SCRATCH.0.as_mut_ptr()) };
        debug_assert_eq!(scratch_ptr.as_ptr() as usize % BITMAP_SLOT_SIZE, 0);

        // SAFETY: `init_once` is called once per task lifetime; backing memory
        // (`MCU_MBOX_SCRATCH`) is `'static` and exclusive to this task.
        static MCU_MBOX_ALLOC_CELL: StaticBitmapAllocatorCell = StaticBitmapAllocatorCell::new();
        let scratch_allocator: &'static BitmapAllocator =
            unsafe { MCU_MBOX_ALLOC_CELL.init_once(scratch_ptr, MCU_MBOX_SCRATCH_SIZE) };
        let scratch = McuMboxScratchAlloc(scratch_allocator);

        // Command handler shared with the Caliptra SPDM VDM backend.
        // Test builds can still replace it with the dedicated integration mock.
        #[cfg(feature = "mcu-mbox-test-handlers")]
        let handler = cmd_handler_mock::NonCryptoCmdHandlerMock;
        #[cfg(not(feature = "mcu-mbox-test-handlers"))]
        let handler = crate::caliptra_cmd_handler::CaliptraCmdBackend;
        // Authorizer: HMAC-based command authorization stays wired in production
        // (uses a placeholder test key for now; to be replaced with real
        // provisioned key material later).
        let mut cmd_authorizer = cmd_auth_mock::MockCommandAuthorizer;
        let mut transport = caliptra_mcu_mbox_lib::transport::McuMboxTransport::new(
            caliptra_mcu_libsyscall_caliptra::mcu_mbox::MCU_MBOX0_DRIVER_NUM,
        );
        let mut mcu_mbox_service = caliptra_mcu_mbox_lib::daemon::McuMboxService::init(
            &handler,
            &mut cmd_authorizer,
            &mut transport,
            &scratch,
        );
        crate::log_info!(
            console_writer,
            "Starting MCU_MBOX service for integration tests..."
        );

        if let Err(e) = mcu_mbox_service.start().await {
            crate::log_error!(
                console_writer,
                "USER_APP: Error starting MCU_MBOX service: {}",
                crate::Dbg(e)
            );
        }
        let suspend_signal: Signal<CriticalSectionRawMutex, ()> = Signal::new();
        suspend_signal.wait().await;
    }

    Ok(())
}
