// Licensed under the Apache-2.0 license

use crate::cmd_interface::{CmdInterface, PLDM_PROTOCOL_CAPABILITIES};
use core::sync::atomic::{AtomicBool, Ordering};
use libsyscall_caliptra::mctp::driver_num;
use libtock_platform::Syscalls;

use romtime::println;
use core::fmt::Write;

pub const MAX_MCTP_PLDM_MSG_SIZE: usize = 1024;

#[derive(Debug)]
pub enum PldmServiceError {
    StartError,
    StopError,
}

pub struct PldmService<'a, S: Syscalls> {
    cmd_interface: CmdInterface<'a, S>,
    running: AtomicBool,
}

impl<'a, S: Syscalls> PldmService<'a, S> {
    pub fn init() -> Self {
        let cmd_interface = CmdInterface::new(driver_num::MCTP_PLDM, &PLDM_PROTOCOL_CAPABILITIES);
        Self {
            cmd_interface,
            running: AtomicBool::new(false),
        }
    }

    pub async fn start(&mut self) -> Result<(), PldmServiceError> {
        // if already started, return error
        if self.running.load(Ordering::SeqCst) {
            return Err(PldmServiceError::StartError);
        }

        println!("[pldm-lib]Starting PLDM service");

        self.running.store(true, Ordering::SeqCst);

        let cmd_interface = &mut self.cmd_interface;
        let running = &self.running;
        let mut msg_buffer: [u8; MAX_MCTP_PLDM_MSG_SIZE] = [0; MAX_MCTP_PLDM_MSG_SIZE];
        while running.load(Ordering::SeqCst) {
            let _ = cmd_interface.handle_msg(&mut msg_buffer).await;
        }

        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
