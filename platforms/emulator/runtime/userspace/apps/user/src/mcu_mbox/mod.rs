// Licensed under the Apache-2.0 license

#[cfg(any(
    feature = "test-mcu-mbox-cmds",
    feature = "test-mcu-mbox-fips-self-test",
    feature = "test-mcu-mbox-fips-periodic",
    feature = "test-caliptra-util-host-validator"
))]
mod cmd_auth_mock;
#[cfg(any(
    feature = "test-mcu-mbox-cmds",
    feature = "test-mcu-mbox-fips-self-test",
    feature = "test-mcu-mbox-fips-periodic",
    feature = "test-caliptra-util-host-validator"
))]
mod cmd_handler_mock;

use caliptra_mcu_libsyscall_caliptra::system::System;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_platform::ErrorCode;
use core::fmt::Write;
#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::signal::Signal;

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
    writeln!(console_writer, "Starting MCU_MBOX task...").unwrap();

    #[cfg(any(
        feature = "test-mcu-mbox-cmds",
        feature = "test-mcu-mbox-fips-self-test",
        feature = "test-mcu-mbox-fips-periodic",
        feature = "test-caliptra-util-host-validator"
    ))]
    {
        let handler = cmd_handler_mock::NonCryptoCmdHandlerMock::default();
        let cmd_authorizer = cmd_auth_mock::MockCommandAuthorizer;
        let mut transport = caliptra_mcu_mbox_lib::transport::McuMboxTransport::new(
            caliptra_mcu_libsyscall_caliptra::mcu_mbox::MCU_MBOX0_DRIVER_NUM,
        );
        let mut mcu_mbox_service = caliptra_mcu_mbox_lib::daemon::McuMboxService::init(
            &handler,
            &cmd_authorizer,
            &mut transport,
            crate::EXECUTOR.get().spawner(),
        );
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
        let suspend_signal: Signal<CriticalSectionRawMutex, ()> = Signal::new();
        suspend_signal.wait().await;
    }

    Ok(())
}
