// Licensed under the Apache-2.0 license

use crate::cmd_interface::{CmdInterface, McuMboxScratch};
use crate::transport::McuMboxTransport;
use caliptra_mcu_common_commands::{CaliptraCmdHandler, CommandAuthorizer};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_userlog::{log_error, Hex32};
#[allow(unused_imports)]
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub enum McuMboxServiceError {
    StartError,
    StopError,
}

/// MCU mailbox service.
///
/// Encapsulates the command interface and running state for the MCU mailbox service.
///
/// Fields:
/// - `cmd_interface`: Handles mailbox commands.
/// - `running`: Indicates if the service is active.
pub struct McuMboxService<
    'a,
    H: CaliptraCmdHandler + 'static,
    A: CommandAuthorizer + 'static,
    Alloc: McuMboxScratch + 'static,
> {
    cmd_interface: CmdInterface<'a, H, A, Alloc>,
    running: &'static AtomicBool,
}

impl<'a, H, A, Alloc> McuMboxService<'a, H, A, Alloc>
where
    H: CaliptraCmdHandler + 'static,
    A: CommandAuthorizer + 'static,
    Alloc: McuMboxScratch + 'static,
{
    pub fn init(
        non_crypto_cmd_handler: &'a H,
        cmd_authorizer: &'a mut A,
        transport: &'a mut McuMboxTransport,
        scratch: &'a Alloc,
    ) -> Self {
        let cmd_interface =
            CmdInterface::new(transport, non_crypto_cmd_handler, cmd_authorizer, scratch);
        Self {
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

        mcu_mbox_responder(&mut self.cmd_interface, self.running).await;
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

pub async fn mcu_mbox_responder<H, A, Alloc>(
    cmd_interface: &mut CmdInterface<'_, H, A, Alloc>,
    running: &'static AtomicBool,
) where
    H: CaliptraCmdHandler,
    A: CommandAuthorizer,
    Alloc: McuMboxScratch,
{
    while running.load(Ordering::SeqCst) {
        if let Err(e) = cmd_interface.handle_responder_msg_from_scratch().await {
            log_error!(
                Console::<DefaultSyscalls>::writer(),
                "mcu_mbox_responder error={}",
                Hex32(u32::from(e))
            );
        }
    }
}
