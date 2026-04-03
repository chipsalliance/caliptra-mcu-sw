// Licensed under the Apache-2.0 license

use crate::cmd_interface::CmdInterface;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_executor::Spawner;
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

/// Global running flag for the VDM service.
static VDM_SERVICE_RUNNING: AtomicBool = AtomicBool::new(false);

/// Spawn the VDM responder task.
///
/// This function spawns an async task that handles VDM requests. The caller is
/// responsible for providing a `CmdInterface` with `'static` lifetime, typically
/// by creating it with static storage using `StaticCell` or similar.
///
/// # Arguments
///
/// * `spawner` - The embassy executor spawner.
/// * `cmd_interface` - A mutable reference to the command interface with `'static` lifetime.
///
/// # Example
///
/// ```ignore
/// static CMD_INTERFACE: StaticCell<CmdInterface<'static>> = StaticCell::new();
///
/// let cmd_interface = CMD_INTERFACE.init(CmdInterface::new(transport, handler));
/// spawn_vdm_responder(spawner, cmd_interface)?;
/// ```
pub fn spawn_vdm_responder(
    spawner: Spawner,
    cmd_interface: &'static mut CmdInterface<'static>,
) -> Result<(), VdmServiceError> {
    if VDM_SERVICE_RUNNING.load(Ordering::SeqCst) {
        return Err(VdmServiceError::StartError);
    }

    VDM_SERVICE_RUNNING.store(true, Ordering::SeqCst);

    spawner
        .spawn(vdm_responder_task(cmd_interface, &VDM_SERVICE_RUNNING))
        .map_err(|_| VdmServiceError::StartError)?;

    Ok(())
}

/// Stop the VDM service.
///
/// Signals the responder task to stop processing new requests.
pub fn stop_vdm_service() {
    VDM_SERVICE_RUNNING.store(false, Ordering::Relaxed);
}

/// Check if the VDM service is running.
pub fn is_vdm_service_running() -> bool {
    VDM_SERVICE_RUNNING.load(Ordering::SeqCst)
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
