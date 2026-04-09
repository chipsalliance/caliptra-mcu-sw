// Licensed under the Apache-2.0 license

#[cfg(any(
    feature = "test-mctp-vdm-cmds",
    feature = "test-caliptra-util-host-mctp-vdm-validator"
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
#[cfg(any(
    feature = "test-mctp-vdm-cmds",
    feature = "test-caliptra-util-host-mctp-vdm-validator"
))]
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

    #[cfg(any(
        feature = "test-mctp-vdm-cmds",
        feature = "test-caliptra-util-host-mctp-vdm-validator"
    ))]
    {
        // Use static storage to ensure 'static lifetime for handler, transport, and cmd_interface.
        static HANDLER: StaticCell<cmd_handler_mock::NonCryptoCmdHandlerMock> = StaticCell::new();
        static TRANSPORT: StaticCell<caliptra_mcu_mctp_vdm_lib::transport::MctpVdmTransport> =
            StaticCell::new();
        static CMD_INTERFACE: StaticCell<
            caliptra_mcu_mctp_vdm_lib::cmd_interface::CmdInterface<'static>,
        > = StaticCell::new();

        let handler: &'static cmd_handler_mock::NonCryptoCmdHandlerMock =
            HANDLER.init(cmd_handler_mock::NonCryptoCmdHandlerMock::default());
        let transport: &'static mut caliptra_mcu_mctp_vdm_lib::transport::MctpVdmTransport =
            TRANSPORT.init(caliptra_mcu_mctp_vdm_lib::transport::MctpVdmTransport::default());

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
        let cmd_interface: &'static mut caliptra_mcu_mctp_vdm_lib::cmd_interface::CmdInterface<
            'static,
        > = CMD_INTERFACE.init(caliptra_mcu_mctp_vdm_lib::cmd_interface::CmdInterface::new(
            transport, handler,
        ));

        writeln!(
            console_writer,
            "Starting MCTP VDM service for integration tests..."
        )
        .unwrap();

        if let Err(e) = caliptra_mcu_mctp_vdm_lib::daemon::spawn_vdm_responder(
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
