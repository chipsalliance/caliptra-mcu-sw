// Licensed under the Apache-2.0 license

#[cfg(feature = "mcu-mbox-service")]
pub(crate) mod cmd_auth_asym;
#[cfg(feature = "mcu-mbox-service")]
mod cmd_handler_mock;

use caliptra_mcu_libsyscall_caliptra::system::System;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_platform::ErrorCode;
#[allow(unused_imports)]
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
    crate::log_info!(console_writer, "Starting MCU_MBOX task...");

    #[cfg(feature = "mcu-mbox-service")]
    {
        let handler = cmd_handler_mock::NonCryptoCmdHandlerMock;
        // Command authorization is the asymmetric, manifest-anchored authorizer
        // (ECDSA-P384 + ML-DSA-87, verified in Caliptra core). It replaced the
        // dummy-HMAC mock. `CmdInterface`/`McuMboxService` see only
        // `&mut dyn CommandAuthorizer`. NOTE: this build only compiles against a
        // caliptra-* rev that carries the VENDOR_AUTH_* commands (currently the
        // fork pin — see VENDOR_AUTH_FORK_PIN_REVERT.md); do not merge to main-2.1
        // until that lands upstream and the pin is reverted.
        let mut cmd_authorizer = cmd_auth_asym::AsymCommandAuthorizer::default();
        let mut transport = caliptra_mcu_mbox_lib::transport::McuMboxTransport::new(
            caliptra_mcu_libsyscall_caliptra::mcu_mbox::MCU_MBOX0_DRIVER_NUM,
        );
        let mut mcu_mbox_service = caliptra_mcu_mbox_lib::daemon::McuMboxService::init(
            &handler,
            &mut cmd_authorizer,
            &mut transport,
            crate::EXECUTOR.get().spawner(),
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
