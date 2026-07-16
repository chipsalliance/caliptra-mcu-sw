// Licensed under the Apache-2.0 license

#[cfg(any(
    feature = "test-mctp-vdm-cmds",
    feature = "test-caliptra-util-host-mctp-vdm-validator",
    feature = "test-defmt-logging-vdm"
))]
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
    crate::log_info!(console_writer, "Starting MCTP VDM task...");

    {
        use caliptra_mcu_mctp_vdm_lib::daemon::MAX_VDM_MSG_SIZE;

        static mut MCTP_VDM_SCRATCH: [u8; MAX_VDM_MSG_SIZE] = [0u8; MAX_VDM_MSG_SIZE];
        // SAFETY: this task is the sole owner of `MCTP_VDM_SCRATCH`.
        let scratch = unsafe { &mut *core::ptr::addr_of_mut!(MCTP_VDM_SCRATCH) };
        let mut transport = caliptra_mcu_mctp_vdm_lib::transport::MctpVdmTransport::default();

        if !transport.exists() {
            crate::log_warn!(
                console_writer,
                "USER_APP: MCTP VDM driver not found, skipping VDM service"
            );
            return Ok(());
        }

        #[cfg(any(
            feature = "test-mctp-vdm-cmds",
            feature = "test-caliptra-util-host-mctp-vdm-validator",
            feature = "test-defmt-logging-vdm"
        ))]
        let handler = cmd_handler_mock::NonCryptoCmdHandlerMock::default();
        #[cfg(not(any(
            feature = "test-mctp-vdm-cmds",
            feature = "test-caliptra-util-host-mctp-vdm-validator",
            feature = "test-defmt-logging-vdm"
        )))]
        let handler = crate::caliptra_cmd_handler::CaliptraCmdBackend;

        let mut cmd_interface =
            caliptra_mcu_mctp_vdm_lib::cmd_interface::CmdInterface::new(&mut transport, &handler);

        crate::log_info!(
            console_writer,
            "Starting MCTP VDM service for integration tests..."
        );

        caliptra_mcu_mctp_vdm_lib::daemon::vdm_responder(&mut cmd_interface, scratch).await;
        let suspend_signal: Signal<CriticalSectionRawMutex, ()> = Signal::new();
        suspend_signal.wait().await;
    }

    Ok(())
}
