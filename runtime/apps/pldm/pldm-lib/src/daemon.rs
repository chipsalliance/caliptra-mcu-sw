// Licensed under the Apache-2.0 license

use crate::cmd_interface::CmdInterface;
use crate::config;
use crate::firmware_device::fd_context::FirmwareDeviceContext;
use crate::firmware_device::fd_ops::FdOps;

use crate::transport::MctpTransport;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use libsyscall_caliptra::mctp::driver_num;

use libtock_platform::Syscalls;
use libtockasync::{self, TockExecutor};

use crate::timer::AsyncAlarm;

// Debug usage
use core::fmt::Write;
use libtock_console::Console;

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
/// * `initiator_signal` - A signal used to activate the PLDM initiator task.
pub struct PldmService<'a, S: Syscalls> {
    spawner : Spawner,
    cmd_interface: CmdInterface<'a, S>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
}

// Note: This implementation is a starting point for integration testing.
// It will be extended and refactored to support additional PLDM commands in both responder and requester modes.
impl<'a, S: Syscalls> PldmService<'a, S> {
    pub fn init(fdops: &'a dyn FdOps, spawner : Spawner) -> Self {
        let cmd_interface = CmdInterface::new(
            config::PLDM_PROTOCOL_CAPABILITIES.get(),
            FirmwareDeviceContext::new(fdops),
        );
        Self {
            spawner,
            cmd_interface,
            running: {
                static RUNNING: AtomicBool = AtomicBool::new(false);
                &RUNNING
            },
            initiator_signal: {
                static INITIATOR_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
                &INITIATOR_SIGNAL
            },
        }
    }

    pub async fn start(&mut self) -> Result<(), PldmServiceError> {
        if self.running.load(Ordering::SeqCst) {
            return Err(PldmServiceError::StartError);
        }

        self.running.store(true, Ordering::SeqCst);

        let cmd_interface: &'static CmdInterface<'static, libtock_runtime::TockSyscalls> =
            unsafe { core::mem::transmute(&self.cmd_interface) };

        self.spawner
            .spawn(pldm_responder_task(
                cmd_interface,
                self.running,
                self.initiator_signal,
            ))
            .unwrap();

        self.spawner
            .spawn(pldm_initiator_task(
                cmd_interface,
                self.running,
                self.initiator_signal,
            ))
            .unwrap();
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[embassy_executor::task]
pub async fn pldm_initiator_task(
    cmd_interface: &'static CmdInterface<'static, libtock_runtime::TockSyscalls>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    pldm_initiator::<libtock_runtime::TockSyscalls>(cmd_interface, running, initiator_signal).await;
}

#[embassy_executor::task]
pub async fn pldm_responder_task(
    cmd_interface: &'static CmdInterface<'static, libtock_runtime::TockSyscalls>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    pldm_responder::<libtock_runtime::TockSyscalls>(cmd_interface, running, initiator_signal).await;
}

pub async fn pldm_initiator<S: Syscalls>(
    cmd_interface: &'static CmdInterface<'static, S>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    // Wait for signal from responder before starting the loop
    initiator_signal.wait().await;

    let mut msg_buffer = [0; MAX_MCTP_PLDM_MSG_SIZE];

    let mut transport = MctpTransport::<S>::new(driver_num::MCTP_PLDM);

    // Print out message that the initiator task has started
    let mut console_writer = Console::<S>::writer();
    writeln!(
        console_writer,
        "[xs debug]pldm_dameon: Initiator task started"
    )
    .unwrap();

    while running.load(Ordering::SeqCst) {
        if cmd_interface.is_stop_initiator_mode().await {
            AsyncAlarm::<S>::sleep(libtock_alarm::Milliseconds(1000)).await;
            break;
        }
        let _ = cmd_interface
            .initiate_firmware_request(&mut transport, &mut msg_buffer)
            .await;
    }
}

pub async fn pldm_responder<S: Syscalls>(
    cmd_interface: &'static CmdInterface<'static, S>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    let mut transport = MctpTransport::<S>::new(driver_num::MCTP_PLDM);

    let mut msg_buffer = [0; MAX_MCTP_PLDM_MSG_SIZE];

    // Print out message that the initiator task has started
    let mut console_writer = Console::<S>::writer();
    writeln!(
        console_writer,
        "[xs debug]pldm_dameon: responder task started"
    )
    .unwrap();

    while running.load(Ordering::SeqCst) {
        // Directly access cmd_interface without locking
        let _ = cmd_interface
            .handle_msg(&mut transport, &mut msg_buffer)
            .await;

        // When FD state is download state, signal the initiator task
        if cmd_interface.is_start_initiator_mode().await && !initiator_signal.signaled() {
            initiator_signal.signal(());
        }
    }
}
