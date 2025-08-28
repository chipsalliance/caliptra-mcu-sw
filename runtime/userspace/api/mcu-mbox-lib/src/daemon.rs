// Licensed under the Apache-2.0 license

use crate::cmd_interface::CmdInterface;
use crate::transport::McuMboxTransport;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_executor::Spawner;
use external_cmds_common::UnifiedCommandHandler;
//use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
//use embassy_sync::signal::Signal;
use libsyscall_caliptra::mcu_mbox::MCU_MBOX0_DRIVER_NUM;

use libtock_alarm::Milliseconds;

pub const MAX_MCU_MBOX_MSG_SIZE: usize = 2048;

#[derive(Debug)]
pub enum PldmServiceError {
    StartError,
    StopError,
}

/// Represents a MCU mailbox service.
///
/// The `McuMboxService` struct encapsulates the command interface and the running state
/// of the PLDM service.
///
/// # Type Parameters
///
/// * `'a` - A lifetime parameter for the command interface.
///
/// # Fields
///
/// * `cmd_interface` - The command interface used by the PLDM service.
/// * `running` - An atomic boolean indicating whether the PLDM service is currently running.
/// * `initiator_signal` - A signal used to activate the PLDM initiator task.
pub struct McuMboxService<'a> {
    spawner: Spawner,
    cmd_interface: CmdInterface<'a>,
    running: &'static AtomicBool,
}

// Note: This implementation is a starting point for integration testing.
// It will be extended and refactored to support additional PLDM commands in both responder and requester modes.
impl<'a> McuMboxService<'a> {
    pub fn init(
        non_crypto_cmd_handler: &'a dyn UnifiedCommandHandler,
        transport: &'a mut McuMboxTransport,
        spawner: Spawner,
    ) -> Self {
        //let mut transport = McuMboxTransport::new(MCU_MBOX0_DRIVER_NUM);

        let cmd_interface = CmdInterface::new(transport, non_crypto_cmd_handler);
        Self {
            spawner,
            cmd_interface,
            running: {
                static RUNNING: AtomicBool = AtomicBool::new(false);
                &RUNNING
            },
        }
    }

    pub async fn start(&mut self) -> Result<(), PldmServiceError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(PldmServiceError::StartError);
        }

        self.running.store(true, Ordering::SeqCst);

        let cmd_interface: &'static mut CmdInterface<'static> =
            unsafe { core::mem::transmute(&mut self.cmd_interface) };

        self.spawner
            .spawn(mcu_mbox_responder_task(cmd_interface, self.running))
            .unwrap();

        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[embassy_executor::task]
pub async fn mcu_mbox_responder_task(
    cmd_interface: &'static mut CmdInterface<'static>,
    running: &'static AtomicBool,
) {
    mcu_mbox_responder(cmd_interface, running).await;
}

pub async fn mcu_mbox_responder(
    cmd_interface: &'static mut CmdInterface<'static>,
    running: &'static AtomicBool,
) {
    let mut msg_buffer = [0; MAX_MCU_MBOX_MSG_SIZE];

    while running.load(Ordering::SeqCst) {
        let _ = cmd_interface.handle_responder_msg(&mut msg_buffer).await;
    }
}
