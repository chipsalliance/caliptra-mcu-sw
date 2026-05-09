// Licensed under the Apache-2.0 license

use crate::cmd_interface::CmdInterface;
use crate::config;
use crate::firmware_device::fd_context::FirmwareDeviceContext;
use crate::firmware_device::fd_ops::FdOps;
use crate::firmware_device::transfer_session::TransferSession;
use crate::timer::AsyncAlarm;
use crate::transport::MctpTransport;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use libsyscall_caliptra::mctp::driver_num;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;
use pldm_common::codec::PldmCodec;
use pldm_common::message::firmware_update::request_fw_data::{
    RequestFirmwareDataRequest, RequestFirmwareDataResponseFixed,
};
use pldm_common::message::firmware_update::transfer_complete::TransferResult;
use pldm_common::protocol::base::{PldmBaseCompletionCode, PldmMsgType};
use pldm_common::protocol::firmware_update::{FwUpdateCmd, FwUpdateCompletionCode};
use pldm_common::util::mctp_transport::{
    construct_mctp_pldm_msg, extract_pldm_msg, PLDM_MSG_OFFSET,
};

pub const MAX_MCTP_PLDM_MSG_SIZE: usize = 1024;
const YIELD_EVERY_ITERATIONS: u32 = 32;

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
///
/// # Fields
///
/// * `cmd_interface` - The command interface used by the PLDM service.
/// * `running` - An atomic boolean indicating whether the PLDM service is currently running.
/// * `initiator_signal` - A signal used to activate the PLDM initiator task.
pub struct PldmService<'a> {
    spawner: Spawner,
    cmd_interface: CmdInterface<'a>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
}

// Note: This implementation is a starting point for integration testing.
// It will be extended and refactored to support additional PLDM commands in both responder and requester modes.
impl<'a> PldmService<'a> {
    pub fn init(fdops: &'a dyn FdOps, spawner: Spawner) -> Self {
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

        let cmd_interface: &'static CmdInterface<'static> =
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
    cmd_interface: &'static CmdInterface<'static>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    pldm_initiator(cmd_interface, running, initiator_signal).await;
}

#[embassy_executor::task]
pub async fn pldm_responder_task(
    cmd_interface: &'static CmdInterface<'static>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    pldm_responder(cmd_interface, running, initiator_signal).await;
}

pub async fn pldm_initiator(
    cmd_interface: &'static CmdInterface<'static>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    let mut console_writer = Console::<DefaultSyscalls>::writer();
    loop {
        // Wait for signal from responder before starting the loop
        initiator_signal.wait().await;

        if !running.load(Ordering::SeqCst) {
            break;
        }

        let mut msg_buffer = [0; MAX_MCTP_PLDM_MSG_SIZE];
        let mut transport = MctpTransport::new(driver_num::MCTP_PLDM);

        // Transfer session for optimized download - created lazily when entering download phase
        let mut session: Option<TransferSession> = None;
        let mut counter: u32 = 0;

        while running.load(Ordering::SeqCst) {
            if cmd_interface.should_stop_initiator_mode().await {
                break;
            }

            // Use optimized download path when we have an active session
            if let Some(ref mut sess) = session {
                match run_optimized_download(cmd_interface, &mut transport, &mut msg_buffer, sess)
                    .await
                {
                    Ok(download_complete) => {
                        if download_complete {
                            // Sync session state back to internal state
                            cmd_interface.sync_transfer_session(sess).await;
                            session = None;
                            // Fall through to regular handling for TransferComplete/Verify/Apply
                        }
                    }
                    Err(e) => {
                        writeln!(
                            console_writer,
                            "PLDM_APP: Error in optimized download: {:?}",
                            e
                        )
                        .unwrap();
                        // Sync and fall back to regular path
                        cmd_interface.sync_transfer_session(sess).await;
                        session = None;
                    }
                }
            }

            if session.is_some() {
                // yield every so often still so that we handle cancelations
                counter = counter.wrapping_add(1);
                if counter % YIELD_EVERY_ITERATIONS == 0 {
                    let _ = AsyncAlarm::<DefaultSyscalls>::sleep_ticks(1).await;
                }
            } else {
                // Handle phases via regular path, which will properly wait for Download state
                match cmd_interface
                    .handle_initiator_msg(&mut transport, &mut msg_buffer)
                    .await
                {
                    Ok(_) => {
                        // After successful handling, check if we should switch to optimized download
                        // The regular handler will have processed the first chunk; now create session
                        // for subsequent chunks if we're still in download phase
                        if cmd_interface.should_start_initiator_mode().await {
                            session = Some(cmd_interface.create_transfer_session().await);
                            counter = 0;
                        }
                    }
                    Err(e) => {
                        writeln!(
                            console_writer,
                            "PLDM_APP: Error handling initiator msg: {:?}",
                            e
                        )
                        .unwrap();
                    }
                }

                // Sleep to yield control to other tasks (only in non-optimized path)
                let _ = AsyncAlarm::<DefaultSyscalls>::sleep_ticks(1).await;
            }
        }
    }
}

pub async fn pldm_responder(
    cmd_interface: &'static CmdInterface<'static>,
    running: &'static AtomicBool,
    initiator_signal: &'static Signal<CriticalSectionRawMutex, ()>,
) {
    let mut transport = MctpTransport::new(driver_num::MCTP_PLDM);

    let mut msg_buffer = [0; MAX_MCTP_PLDM_MSG_SIZE];
    let mut console_writer = Console::<DefaultSyscalls>::writer();

    while running.load(Ordering::SeqCst) {
        match cmd_interface
            .handle_responder_msg(&mut transport, &mut msg_buffer)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                writeln!(
                    console_writer,
                    "PLDM_APP: Error handling responder msg: {:?}",
                    e
                )
                .unwrap();
            }
        }

        // When FD state is download state, signal the initiator task
        if cmd_interface.should_start_initiator_mode().await && !initiator_signal.signaled() {
            initiator_signal.signal(());
        }
    }
}

/// Optimized download loop that uses a local TransferSession to minimize mutex acquisitions.
///
/// This function runs the download phase with the session state kept outside the async mutex,
/// only syncing back periodically or when the transfer completes/is cancelled.
async fn run_optimized_download(
    cmd_interface: &'static CmdInterface<'static>,
    transport: &mut MctpTransport,
    msg_buffer: &mut [u8],
    session: &mut TransferSession,
) -> Result<bool, crate::error::MsgHandlerError> {
    let ua_eid: u8 = crate::config::UA_EID;
    let ops = cmd_interface.ops();

    // Check for cancellation (atomic, no mutex)
    if cmd_interface.is_cancelled() {
        session.mark_complete(TransferResult::FdAbortedTransfer);
        return Ok(true); // Signal that download phase is done
    }

    let now = cmd_interface.now();

    // Check T1 timeout
    if session.is_t1_timeout(now) {
        session.mark_failed(TransferResult::FdAbortedTransfer);
        return Ok(true);
    }

    // Check if we should send a request
    if !session.should_send_request(now) {
        return Ok(false);
    }

    // If transfer is complete, signal done (TransferComplete will be handled by fallback path)
    if session.complete {
        return Ok(true);
    }

    // Query offset and length from ops (this is an async call but necessary)
    let (requested_offset, requested_length) = ops
        .query_download_offset_and_length(&session.component)
        .await
        .map_err(crate::error::MsgHandlerError::FdOps)?;

    // Calculate chunk parameters using local session state
    let (chunk_offset, chunk_length) =
        match session.get_download_chunk(requested_offset as u32, requested_length as u32) {
            Some(chunk) => chunk,
            None => {
                session.mark_failed(TransferResult::FdAbortedTransfer);
                return Ok(true);
            }
        };

    // Update session state
    session.offset = chunk_offset;
    session.length = chunk_length;

    // Build request message
    let instance_id = session.alloc_next_instance_id();
    let payload =
        construct_mctp_pldm_msg(msg_buffer).map_err(crate::error::MsgHandlerError::Util)?;

    let msg_len = RequestFirmwareDataRequest::new(
        instance_id,
        PldmMsgType::Request,
        chunk_offset,
        chunk_length,
    )
    .encode(payload)
    .map_err(crate::error::MsgHandlerError::Codec)?;

    // Mark as sent
    session.mark_sent(cmd_interface.now(), FwUpdateCmd::RequestFirmwareData as u8);

    // Send request
    transport
        .send_request(ua_eid, &msg_buffer[..msg_len + PLDM_MSG_OFFSET])
        .await
        .map_err(crate::error::MsgHandlerError::Transport)?;

    // Receive response
    transport
        .receive_response(msg_buffer)
        .await
        .map_err(crate::error::MsgHandlerError::Transport)?;

    // Process response
    let resp_payload = extract_pldm_msg(msg_buffer).map_err(crate::error::MsgHandlerError::Util)?;

    let rsp_fixed = RequestFirmwareDataResponseFixed::decode(resp_payload)
        .map_err(crate::error::MsgHandlerError::Codec)?;

    // Update T1 timestamp on response
    session.update_t1_timestamp(cmd_interface.now());

    match rsp_fixed.completion_code {
        code if code == PldmBaseCompletionCode::Success as u8 => {
            // Extract firmware data and pass to ops
            let fw_data = &resp_payload[core::mem::size_of::<RequestFirmwareDataResponseFixed>()..]
                .get(..chunk_length as usize)
                .ok_or(crate::error::MsgHandlerError::Codec(
                    pldm_common::codec::PldmCodecError::BufferTooShort,
                ))?;

            let result = ops
                .download_fw_data(chunk_offset as usize, fw_data, &session.component)
                .await
                .map_err(crate::error::MsgHandlerError::FdOps)?;

            if result == TransferResult::TransferSuccess {
                if ops.is_download_complete(&session.component) {
                    session.mark_complete(TransferResult::TransferSuccess);
                    return Ok(true);
                } else {
                    session.mark_ready_for_next();
                }
            } else {
                session.mark_complete(result);
                return Ok(true);
            }
        }
        code if code == FwUpdateCompletionCode::RetryRequestFwData as u8 => {
            // Retry - keep state as ready
            session.mark_ready_for_next();
        }
        _ => {
            session.mark_complete(TransferResult::FdAbortedTransfer);
            return Ok(true);
        }
    }

    Ok(false)
}
