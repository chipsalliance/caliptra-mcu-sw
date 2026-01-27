// Licensed under the Apache-2.0 license

#[cfg(feature = "test-mctp-vdm-cmds")]
mod cmd_handler_mock;

use core::fmt::Write;
#[allow(unused)]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[allow(unused)]
use embassy_sync::signal::Signal;
use libsyscall_caliptra::system::System;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;
use libtock_platform::ErrorCode;

#[embassy_executor::task]
pub async fn vdm_task() {
    match start_vdm_service().await {
        Ok(_) => {}
        Err(_) => System::exit(1),
    }
}

#[allow(dead_code)]
#[allow(unused_variables)]
async fn start_vdm_service() -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    writeln!(console_writer, "Starting MCTP VDM task...").unwrap();

    #[cfg(feature = "test-mctp-vdm-cmds")]
    {
        let handler = cmd_handler_mock::NonCryptoCmdHandlerMock::default();
        let mut transport = mctp_vdm_lib::transport::MctpVdmTransport::default();

        // Check if the transport driver exists
        if !transport.exists() {
            writeln!(
                console_writer,
                "USER_APP: MCTP VDM driver not found, skipping VDM service"
            )
            .unwrap();
            return Ok(());
        }

        let mut vdm_service = mctp_vdm_lib::daemon::VdmService::init(
            &handler,
            &mut transport,
            crate::EXECUTOR.get().spawner(),
        );
        writeln!(
            console_writer,
            "Starting MCTP VDM service for integration tests..."
        )
        .unwrap();

        if let Err(e) = vdm_service.start().await {
            writeln!(
                console_writer,
                "USER_APP: Error starting MCTP VDM service: {:?}",
                e
            )
            .unwrap();
        }
        let suspend_signal: Signal<CriticalSectionRawMutex, ()> = Signal::new();
        suspend_signal.wait().await;
    }

    Ok(())
}
