// Licensed under the Apache-2.0 license

mod cmd_handler_mock;
mod config;

use core::fmt::Write;

use libtock_console::Console;
use libtock_platform::ErrorCode;

use libsyscall_caliptra::mcu_mbox::MCU_MBOX0_DRIVER_NUM;
use mcu_mbox_lib::daemon::McuMboxService;
use mcu_mbox_lib::transport::{McuMboxTransport, TransportError};

use crate::EXECUTOR;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::{lazy_lock::LazyLock, signal::Signal};
use libsyscall_caliptra::DefaultSyscalls;
use zerocopy::{FromBytes, IntoBytes};

#[embassy_executor::task]
pub async fn mcu_mbox_task() {
    match start_mcu_mbox_service().await {
        Ok(_) => {}
        Err(_) => romtime::test_exit(1),
    }
    #[cfg(not(feature = "test-mcu-mbox-cmds"))]
    romtime::test_exit(0);
}

#[allow(dead_code)]
#[allow(unused_variables)]
async fn start_mcu_mbox_service() -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "Starting MCU_MBOX task...").unwrap();

    #[cfg(feature = "test-mcu-mbox-cmds")]
    {
        let handler = cmd_handler_mock::NonCryptoCmdHandlerMock::new();
        let mut transport = McuMboxTransport::new(MCU_MBOX0_DRIVER_NUM);
        let mut mcu_mbox_service =
            McuMboxService::init(&handler, &mut transport, EXECUTOR.get().spawner());
        writeln!(
            console_writer,
            "Starting MCU_MBOX service for integration tests..."
        )
        .unwrap();

        if let Err(e) = mcu_mbox_service.start().await {
            writeln!(
                console_writer,
                "USER_APP: Error starting MCU_MBOX service: {:?}",
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
