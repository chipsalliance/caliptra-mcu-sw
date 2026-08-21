// Licensed under the Apache-2.0 license

use crate::cmd_interface::CmdInterface;
use caliptra_mcu_common_commands::CaliptraCmdHandler;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_userlog::{log_error, Dbg};
#[allow(unused_imports)]
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

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

/// VDM responder loop.
pub async fn vdm_responder<H: CaliptraCmdHandler>(
    cmd_interface: &mut CmdInterface<'_, H>,
    msg_buffer: &mut [u8],
) {
    VDM_SERVICE_RUNNING.store(true, Ordering::SeqCst);
    while VDM_SERVICE_RUNNING.load(Ordering::SeqCst) {
        if let Err(e) = cmd_interface.handle_responder_msg(msg_buffer).await {
            log_error!(
                Console::<DefaultSyscalls>::writer(),
                "vdm_responder error={}",
                Dbg(e)
            );
        }
    }
}
