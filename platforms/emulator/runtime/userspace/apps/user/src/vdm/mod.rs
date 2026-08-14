// Licensed under the Apache-2.0 license

use caliptra_mcu_libsyscall_caliptra::system::System;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_platform::ErrorCode;
#[allow(unused_imports)]
use core::fmt::Write;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use static_cell::StaticCell;

use crate::caliptra_cmd_handler::CaliptraCmdBackend as VdmHandler;

#[embassy_executor::task]
pub async fn vdm_task() {
    match start_vdm_service().await {
        Ok(_) => {}
        Err(_) => System::exit(1),
    }
}

async fn start_vdm_service() -> Result<(), ErrorCode> {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    crate::log_info!(console_writer, "Starting MCTP VDM task...");

    // Use static storage to ensure 'static lifetime for handler, transport, and cmd_interface.
    static HANDLER: StaticCell<VdmHandler> = StaticCell::new();
    static TRANSPORT: StaticCell<caliptra_mcu_mctp_vdm_lib::transport::MctpVdmTransport> =
        StaticCell::new();
    static CMD_INTERFACE: StaticCell<
        caliptra_mcu_mctp_vdm_lib::cmd_interface::CmdInterface<'static, VdmHandler>,
    > = StaticCell::new();
    static MSG_BUFFER: StaticCell<[u8; caliptra_mcu_mctp_vdm_lib::daemon::MAX_VDM_MSG_SIZE]> =
        StaticCell::new();

    let handler: &'static VdmHandler = HANDLER.init(VdmHandler);
    let transport: &'static mut caliptra_mcu_mctp_vdm_lib::transport::MctpVdmTransport =
        TRANSPORT.init(caliptra_mcu_mctp_vdm_lib::transport::MctpVdmTransport::default());

    // Check if the transport driver exists
    if !transport.exists() {
        crate::log_warn!(
            console_writer,
            "USER_APP: MCTP VDM driver not found, skipping VDM service"
        );
        return Ok(());
    }

    // Create the command interface with static storage
    let cmd_interface: &'static mut caliptra_mcu_mctp_vdm_lib::cmd_interface::CmdInterface<
        'static,
        VdmHandler,
    > = CMD_INTERFACE.init(caliptra_mcu_mctp_vdm_lib::cmd_interface::CmdInterface::new(
        transport, handler,
    ));

    crate::log_info!(console_writer, "Starting MCTP VDM service...");

    let msg_buffer = MSG_BUFFER.init([0; caliptra_mcu_mctp_vdm_lib::daemon::MAX_VDM_MSG_SIZE]);
    caliptra_mcu_mctp_vdm_lib::daemon::vdm_responder(cmd_interface, msg_buffer).await;
    let suspend_signal: Signal<CriticalSectionRawMutex, ()> = Signal::new();
    suspend_signal.wait().await;

    Ok(())
}
