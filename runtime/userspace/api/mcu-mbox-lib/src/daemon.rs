// Licensed under the Apache-2.0 license

use crate::cmd_interface::CmdInterface;
use crate::transport::McuMboxTransport;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_executor::Spawner;
use external_cmds_common::UnifiedCommandHandler;

const MAX_MCU_MBOX_MSG_SIZE: usize = 2048; // Adjust as needed

#[derive(Debug)]
pub enum McuMboxServiceError {
    StartError,
    StopError,
}

/// MCU mailbox service.
///
/// Encapsulates the command interface, task spawner, and running state for the MCU mailbox service.
///
/// Fields:
/// - `spawner`: Embassy task spawner for running async tasks.
/// - `cmd_interface`: Handles mailbox commands.
/// - `running`: Indicates if the service is active.
pub struct McuMboxService<'a> {
    spawner: Spawner,
    cmd_interface: CmdInterface<'a>,
    running: &'static AtomicBool,
}

impl<'a> McuMboxService<'a> {
    pub fn init(
        non_crypto_cmd_handler: &'a dyn UnifiedCommandHandler,
        transport: &'a mut McuMboxTransport,
        spawner: Spawner,
    ) -> Self {
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

    pub async fn start(&mut self) -> Result<(), McuMboxServiceError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(McuMboxServiceError::StartError);
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
