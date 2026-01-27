// Licensed under the Apache-2.0 license

use crate::cmd_interface::CmdInterface;
use crate::transport::MctpVdmTransport;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_executor::Spawner;
use external_cmds_common::UnifiedCommandHandler;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;

/// Maximum size of VDM message buffer (implementation-defined limit).
pub const MAX_VDM_MSG_SIZE: usize = 1024;

/// VDM Service error types.
#[derive(Debug)]
pub enum VdmServiceError {
    StartError,
    StopError,
}

/// VDM Service.
///
/// Manages the VDM responder task lifecycle.
pub struct VdmService<'a> {
    spawner: Spawner,
    cmd_interface: CmdInterface<'a>,
    running: &'static AtomicBool,
}

impl<'a> VdmService<'a> {
    /// Initialize a new VDM service.
    pub fn init(
        unified_handler: &'a dyn UnifiedCommandHandler,
        transport: &'a mut MctpVdmTransport,
        spawner: Spawner,
    ) -> Self {
        let cmd_interface = CmdInterface::new(transport, unified_handler);
        Self {
            spawner,
            cmd_interface,
            running: {
                static RUNNING: AtomicBool = AtomicBool::new(false);
                &RUNNING
            },
        }
    }

    /// Start the VDM service.
    pub async fn start(&mut self) -> Result<(), VdmServiceError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(VdmServiceError::StartError);
        }

        self.running.store(true, Ordering::SeqCst);

        // SAFETY: We're transmuting the lifetime to 'static because the task
        // will be stopped before the service is dropped.
        let cmd_interface: &'static mut CmdInterface<'static> =
            unsafe { core::mem::transmute(&mut self.cmd_interface) };

        self.spawner
            .spawn(vdm_responder_task(cmd_interface, self.running))
            .unwrap();

        Ok(())
    }

    /// Stop the VDM service.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Check if the service is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// VDM responder task.
#[embassy_executor::task]
pub async fn vdm_responder_task(
    cmd_interface: &'static mut CmdInterface<'static>,
    running: &'static AtomicBool,
) {
    vdm_responder(cmd_interface, running).await;
}

/// VDM responder loop.
pub async fn vdm_responder(
    cmd_interface: &'static mut CmdInterface<'static>,
    running: &'static AtomicBool,
) {
    let mut msg_buffer = [0u8; MAX_VDM_MSG_SIZE];
    while running.load(Ordering::SeqCst) {
        if let Err(e) = cmd_interface.handle_responder_msg(&mut msg_buffer).await {
            // Debug print on error
            writeln!(
                Console::<DefaultSyscalls>::writer(),
                "vdm_responder error: {:?}",
                e
            )
            .unwrap();
        }
    }
}
