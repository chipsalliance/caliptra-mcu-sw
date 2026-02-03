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
#[cfg(feature = "test-mctp-vdm-cmds")]
use static_cell::StaticCell;

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
        // Use static storage to ensure 'static lifetime for handler, transport, and cmd_interface.
        static HANDLER: StaticCell<cmd_handler_mock::NonCryptoCmdHandlerMock> = StaticCell::new();
        static TRANSPORT: StaticCell<mctp_vdm_lib::transport::MctpVdmTransport> = StaticCell::new();
        static CMD_INTERFACE: StaticCell<mctp_vdm_lib::cmd_interface::CmdInterface<'static>> =
            StaticCell::new();

        let handler: &'static cmd_handler_mock::NonCryptoCmdHandlerMock =
            HANDLER.init(cmd_handler_mock::NonCryptoCmdHandlerMock::default());
        let transport: &'static mut mctp_vdm_lib::transport::MctpVdmTransport =
            TRANSPORT.init(mctp_vdm_lib::transport::MctpVdmTransport::default());

        // Check if the transport driver exists
        if !transport.exists() {
            writeln!(
                console_writer,
                "USER_APP: MCTP VDM driver not found, skipping VDM service"
            )
            .unwrap();
            return Ok(());
        }

        // Create the command interface with static storage
        let cmd_interface: &'static mut mctp_vdm_lib::cmd_interface::CmdInterface<'static> =
            CMD_INTERFACE.init(mctp_vdm_lib::cmd_interface::CmdInterface::new(
                transport, handler,
            ));

        writeln!(
            console_writer,
            "Starting MCTP VDM service for integration tests..."
        )
        .unwrap();

        if let Err(e) = mctp_vdm_lib::daemon::spawn_vdm_responder(
            crate::EXECUTOR.get().spawner(),
            cmd_interface,
        ) {
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
