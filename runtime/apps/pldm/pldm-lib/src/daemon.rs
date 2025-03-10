// Licensed under the Apache-2.0 license

use crate::cmd_interface::{CmdInterface, PLDM_PROTOCOL_CAPABILITIES};
use core::sync::atomic::{AtomicBool, Ordering};
use libsyscall_caliptra::mctp::driver_num;
use libtock_platform::Syscalls;

pub const MAX_MCTP_PLDM_MSG_SIZE: usize = 1024;

#[derive(Debug)]
pub enum PldmServiceError {
    StartError,
    StopError,
}

/// Represents a PLDM (Platform Level Data Model) service.
///
/// The `PldmService` struct encapsulates the command interface and the running state
/// of the PLDM service.
///
/// # Type Parameters
///
/// * `'a` - A lifetime parameter for the command interface.
/// * `S` - A type that implements the `Syscalls` trait, representing the system calls
///   used by the command interface.
///
/// # Fields
///
/// * `cmd_interface` - The command interface used by the PLDM service.
/// * `running` - An atomic boolean indicating whether the PLDM service is currently running.
pub struct PldmService<'a, S: Syscalls> {
    cmd_interface: CmdInterface<'a, S>,
    running: AtomicBool,
}

// Note: This implementation is a starting point for integration testing.
// It will be extended and refactored to support additional PLDM commands in both responder and requester modes.
impl<'a, S: Syscalls> PldmService<'a, S> {
    pub fn init() -> Self {
        let cmd_interface = CmdInterface::new(driver_num::MCTP_PLDM, &PLDM_PROTOCOL_CAPABILITIES);
        Self {
            cmd_interface,
            running: AtomicBool::new(false),
        }
    }

    pub async fn start(&mut self) -> Result<(), PldmServiceError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(PldmServiceError::StartError);
        }

        self.running.store(true, Ordering::SeqCst);
        let mut msg_buffer = [0; MAX_MCTP_PLDM_MSG_SIZE];
        while self.running.load(Ordering::SeqCst) {
            // TODO: add a timeout to avoid blocking indefinitely
            let _ = self.cmd_interface.handle_msg(&mut msg_buffer).await;
        }
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
