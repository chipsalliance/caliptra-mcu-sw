// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::{
    valid_eid, valid_msg_tag, MessageType, MCTP_TAG_MASK, MCTP_TAG_OWNER,
};
use crate::mctp::recv::MCTPRxClient;
use crate::mctp::send::{MCTPSender, MCTPTxClient};
use core::cell::Cell;
use core::fmt::Write;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::{ErrorCode, ProcessId};
use romtime::println;

pub const MCTP_MAX_MESSAGE_SIZE: usize = 2048;
pub const MCTP_SPDM_DRIVER_NUM: usize = 0xA0000;
pub const MCTP_SECURE_SPDM_DRIVER_NUM: usize = 0xA0001;
pub const MCTP_PLDM_DRIVER_NUM: usize = 0xA0002;
pub const MCTP_CALIPTRA_DRIVER_NUM: usize = 0xA0003;

/// IDs for subscribe calls
mod upcall {
    /// Callback for when the message is received
    pub const RECEIVED_REQUEST: usize = 0;
    pub const RECEIVED_RESPONSE: usize = 1;

    /// Callback for when the message is transmitted.
    pub const MESSAGE_TRANSMITTED: usize = 2;

    /// Number of upcalls
    pub const COUNT: u8 = 3;
}

/// IDs for read-only allow buffers
mod ro_allow {
    /// Buffer for the message to be transmitted
    pub const MESSAGE_WRITE: usize = 0;

    /// Number of read-only allow buffers
    pub const COUNT: u8 = 1;
}

/// IDs for read-write allow buffers
mod rw_allow {
    /// Buffer for the message to be received
    pub const READ_REQUEST: usize = 0;
    pub const READ_RESPONSE: usize = 1;

    /// Number of read-write allow buffers
    pub const COUNT: u8 = 2;
}

/// Structure to hold a buffered message when no application is waiting
#[derive(Debug, Clone, Copy)]
struct BufferedMessage {
    msg_type: u8,
    msg_len: usize,
    recv_time: u32,
    op_context: OpContext,
}

impl BufferedMessage {
    fn matches_pending_operation(&self, pending_op: &OpContext) -> bool {
        // Both buffered and pending operations should be rx operations
        if self.op_context.op_type != OpType::Rx || pending_op.op_type != OpType::Rx {
            return false;
        }

        pending_op.matches(self.op_context.msg_tag, self.op_context.peer_eid)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum OpType {
    Tx,
    Rx,
}

#[derive(Debug, Clone, Copy)]
struct OpContext {
    msg_tag: u8,
    peer_eid: u8,
    op_type: OpType,
}

impl OpContext {
    fn pending_request(&self) -> bool {
        self.msg_tag == MCTP_TAG_OWNER
    }

    fn pending_response(&self) -> bool {
        self.msg_tag & MCTP_TAG_OWNER == 0
    }

    fn matches(&self, msg_tag: u8, peer_eid: u8) -> bool {
        match self.op_type {
            OpType::Rx => {
                if self.pending_request() {
                    return msg_tag & MCTP_TAG_OWNER != 0;
                } else if self.pending_response() {
                    return msg_tag == self.msg_tag && peer_eid == self.peer_eid;
                }
            }
            OpType::Tx => {
                if self.peer_eid == peer_eid {
                    if self.pending_request() {
                        return true;
                    } else if self.pending_response() {
                        return msg_tag == self.msg_tag;
                    }
                }
            }
        }
        false
    }
}

#[derive(Default)]
pub struct App {
    pending_rx_request: Option<OpContext>,
    pending_rx_response: Option<OpContext>,
    pending_tx: Option<OpContext>,
}

pub struct MCTPDriver<'a> {
    sender: &'a dyn MCTPSender<'a>,
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    current_app: Cell<Option<ProcessId>>,
    msg_type: MessageType,
    max_msg_size: usize,
    kernel_msg_buf: MapCell<SubSliceMut<'static, u8>>,
    kernel_rx_buf: TakeCell<'static, [u8]>,
    buffered_message: OptionalCell<BufferedMessage>,
    deferred_call: DeferredCall,
}

impl<'a> MCTPDriver<'a> {
    pub fn new(
        sender: &'a dyn MCTPSender<'a>,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        msg_type: MessageType,
        max_msg_size: usize,
        msg_buf: SubSliceMut<'static, u8>,
        rx_buf: &'static mut [u8],
    ) -> MCTPDriver<'a> {
        MCTPDriver {
            sender,
            apps: grant,
            current_app: Cell::new(None),
            msg_type,
            max_msg_size,
            kernel_msg_buf: MapCell::new(msg_buf),
            kernel_rx_buf: TakeCell::new(rx_buf),
            buffered_message: OptionalCell::empty(),
            deferred_call: DeferredCall::new(),
        }
    }

    fn parse_args(
        &self,
        command_num: usize,
        arg1: usize,
        arg2: usize,
    ) -> Result<(u8, u8), ErrorCode> {
        // arg1 is always peer_eid
        let peer_eid = arg1 as u8;

        if !valid_eid(peer_eid) {
            Err(ErrorCode::INVAL)?;
        }

        // Receive Request message or send Request message should have MCTP_TAG_OWNER
        // Receive Response message or send Response message should have a value between 0 and 7
        let mut msg_tag = (arg2 & 0xFF) as u8;

        if command_num == 1 || command_num == 3 {
            msg_tag = MCTP_TAG_OWNER;
        }

        if (command_num == 2 || command_num == 4) && !valid_msg_tag(msg_tag) {
            Err(ErrorCode::INVAL)?;
        }

        Ok((peer_eid, msg_tag))
    }

    /// Send the message payload to the peer EID.
    /// Copies the message payload from the process buffer to the kernel buffer.
    /// Sends the message to the peer EID.
    /// If the send is successful, the operation context is updated. Otherwise, the result is returned immediately to the caller.
    ///
    /// # Arguments
    /// * `app` - The application context
    /// * `kernel_data` - Application's grant data provided to kernel
    /// * `msg_type` - Message type
    /// * `dest_eid` - Destination EID to send the message to
    /// * `msg_tag` - Message tag of the message. It is MCTP_TAG_OWNER if the message is a request message or
    ///   a value between 0 and 7 if it is a response message.
    ///
    /// # Returns
    /// Returns Ok(()) if the message is successfully submitted to be sent to the peer EID.
    /// Returns NOMEM if the kernel buffer is not available.
    /// Returns SIZE if the message payload is too large for the kernel buffer.
    fn send_msg_payload(
        &self,
        process_id: ProcessId,
        app: &mut App,
        kernel_data: &GrantKernelData,
        dest_eid: u8,
        msg_tag: u8,
    ) -> Result<(), ErrorCode> {
        kernel_data
            .get_readonly_processbuffer(ro_allow::MESSAGE_WRITE)
            .and_then(|write| {
                write.enter(|wpayload| {
                    match self.kernel_msg_buf.take() {
                        Some(mut kernel_msg_buf) => {
                            if wpayload.len() > kernel_msg_buf.len() {
                                return Err(ErrorCode::SIZE);
                            }

                            wpayload.copy_to_slice(&mut kernel_msg_buf[..wpayload.len()]);
                            // Slice the kernel buffer to the length of the message payload
                            kernel_msg_buf.slice(0..wpayload.len());

                            app.pending_tx = Some(OpContext {
                                msg_tag,
                                peer_eid: dest_eid,
                                op_type: OpType::Tx,
                            });
                            self.current_app.set(Some(process_id));
                            match self.sender.send_msg(
                                self.msg_type as u8,
                                dest_eid,
                                msg_tag,
                                kernel_msg_buf,
                            ) {
                                Ok(_) => Ok(()),
                                Err(mut buf) => {
                                    println!("[MCTP-CAPSULE]: send_msg failed");
                                    // Reset the kernel buffer to original size and restore it
                                    buf.reset();
                                    self.kernel_msg_buf.replace(buf);
                                    // clear
                                    app.pending_tx.take();
                                    self.current_app.take();
                                    Err(ErrorCode::FAIL)
                                }
                            }
                        }
                        None => Err(ErrorCode::NOMEM),
                    }
                })
            })
            .unwrap_or_else(|err| err.into())
    }

    fn pending_rx_request(&self, app: &mut App, msg_tag: u8, src_eid: u8) -> bool {
        let op_ctx = match app.pending_rx_request.as_ref() {
            Some(op_ctx) => op_ctx,
            None => {
                return false;
            }
        };

        if !op_ctx.matches(msg_tag, src_eid) {
            return false;
        }

        true
    }

    fn pending_rx_response(&self, app: &mut App, msg_tag: u8, src_eid: u8) -> bool {
        let op_ctx = match app.pending_rx_response.as_ref() {
            Some(op_ctx) => op_ctx,
            None => {
                return false;
            }
        };

        if !op_ctx.matches(msg_tag, src_eid) {
            return false;
        }

        true
    }

    fn tx_pending(&self, app: &mut App, msg_tag: u8, dest_eid: u8) -> bool {
        let op_ctx = match app.pending_tx.as_ref() {
            Some(op_ctx) => op_ctx,
            None => {
                return false;
            }
        };

        if !op_ctx.matches(msg_tag, dest_eid) {
            return false;
        }

        true
    }

    /// Store a message in the buffer when no application is waiting
    /// If there's already a buffered message, replace it with the new one (newer messages take priority)
    fn buffer_message(
        &self,
        src_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        msg_payload: &[u8],
        msg_len: usize,
        recv_time: u32,
    ) -> bool {
        // Check if we already have a buffered message and warn about replacement
        if self.buffered_message.is_some() {
            println!(
                "[MCTP-CAPSULE]::buffer_message replacing existing buffered message with new one (msg_tag={}, {} bytes)",
                msg_tag, msg_len
            );
        }

        // Take the kernel rx buffer to store the message
        if let Some(rx_buf) = self.kernel_rx_buf.take() {
            if msg_len > rx_buf.len() {
                // Message too large, restore buffer and drop message
                self.kernel_rx_buf.replace(rx_buf);
                println!("[MCTP-CAPSULE]::buffer_message message too large for buffer. Dropping message.");
                return false;
            }

            // Copy message to buffer (this overwrites any existing message)
            rx_buf[..msg_len].copy_from_slice(&msg_payload[..msg_len]);

            // Store message metadata (this replaces any existing buffered message)
            let buffered_msg = BufferedMessage {
                msg_type,
                msg_len,
                recv_time,
                op_context: OpContext {
                    msg_tag,
                    peer_eid: src_eid,
                    op_type: OpType::Rx,
                },
            };

            self.buffered_message.set(buffered_msg);
            self.kernel_rx_buf.replace(rx_buf);

            println!(
                "[MCTP-CAPSULE]::buffer_message buffered {} bytes msg tag {}",
                msg_len, msg_tag
            );
            true
        } else {
            println!("[MCTP-CAPSULE]::buffer_message no rx buffer available");
            false
        }
    }

    /// Check if there's a buffered message that matches a pending request or response
    fn check_buffered_message(&self, op_ctx: &OpContext) -> bool {
        if let Some(buffered_msg) = self.buffered_message.take() {
            let matched = buffered_msg.matches_pending_operation(op_ctx);
            self.buffered_message.set(buffered_msg);
            matched
        } else {
            false
        }
    }

    /// Deliver buffered rx message to waiting application
    fn deliver_buffered_message(&self) {
        if let Some(buffered_msg) = self.buffered_message.take() {
            if let Some(rx_buf) = self.kernel_rx_buf.take() {
                // Find the app that matches this buffered message
                self.apps.each(|_, app, kernel_data| {
                    // Check if this buffered message matches a pending request or response
                    let rw_buffer: usize;
                    let rx_request: bool;

                    let request_match = app.pending_rx_request.as_ref().is_some_and(|req_ctx| {
                        buffered_msg.matches_pending_operation(req_ctx)
                    });
                    let response_match = app.pending_rx_response.as_ref().is_some_and(|rsp_ctx| {
                        buffered_msg.matches_pending_operation(rsp_ctx)
                    });

                    if request_match {
                        rw_buffer = rw_allow::READ_REQUEST;
                        rx_request = true;
                    } else if response_match {
                        rw_buffer = rw_allow::READ_RESPONSE;
                        rx_request = false;
                    } else {
                        return; // No match, continue to next app
                    }

                    // Copy the buffered message to the process buffer
                    let res = kernel_data
                        .get_readwrite_processbuffer(rw_buffer)
                        .and_then(|read| {
                            read.mut_enter(|rmsg_payload| {
                                if rmsg_payload.len() < buffered_msg.msg_len {
                                    Err(ErrorCode::SIZE)
                                } else {
                                    rmsg_payload[..buffered_msg.msg_len].copy_from_slice(&rx_buf[..buffered_msg.msg_len]);
                                    Ok(())
                                }
                            })
                        })
                        .unwrap_or(Err(ErrorCode::NOMEM));

                    // Schedule the upcall if the message payload is copied successfully
                    if res.is_ok() {
                        let subscribe_num = if rx_request {
                            app.pending_rx_request = None;
                            upcall::RECEIVED_REQUEST
                        } else {
                            app.pending_rx_response = None;
                            upcall::RECEIVED_RESPONSE
                        };

                        let msg_info =
                            ((buffered_msg.op_context.peer_eid as usize) << 16) | ((buffered_msg.msg_type as usize) << 8) | (buffered_msg.op_context.msg_tag as usize);

                        if let Err(e) = kernel_data.schedule_upcall(
                                subscribe_num,
                            (buffered_msg.msg_len, buffered_msg.recv_time as usize, msg_info),
                        ) {
                            println!("[MCTP-CAPSULE]::deliver_buffered_message upcall schedule failed: {:?}", e);
                        }
                    }
                });

                // Restore the rx buffer
                self.kernel_rx_buf.replace(rx_buf);
            }
        }
    }
}

impl SyscallDriver for MCTPDriver<'_> {
    /// MCTP Capsule command
    ///
    /// ### `command_num`
    ///
    /// - `0`: Driver check.
    ///
    /// - `1`: Receive Request Message.
    /// - `2`: Receive Response Message.
    ///   Returns INVAL if the command arguments are invalid.
    ///   Otherwise, replaces the pending rx operation context with the new one.
    ///   When a new message is received from peer EID, the metadata is compared with the pending rx operation context.
    ///   If the metadata matches, the message is copied to the process buffer and the upcall is scheduled.
    ///
    ///
    /// - `3`: Send Request Message.
    /// - `4`: Send Response Message.
    ///   Sends the message payload to the peer EID.
    ///   Returns INVAL if the command arguments are invalid.
    ///   Returns EBUSY if there is already a pending tx operation.
    ///   Otherwise, returns the result of send_msg_payload(). A successful send_msg_payload() call
    ///   will return Ok(()) and the pending tx operation context is updated. Otherwise, the result is returned immediately.
    ///
    /// - `5`: Get the maximum message size supported by the MCTP driver.
    fn command(
        &self,
        command_num: usize,
        arg1: usize,
        arg2: usize,
        process_id: ProcessId,
    ) -> CommandReturn {
        match command_num {
            0 => CommandReturn::success(),
            // 1: Receive Request Message
            // 2: Receive Response Message
            1 | 2 => {
                let (peer_eid, msg_tag) = match self.parse_args(command_num, arg1, arg2) {
                    Ok((peer_eid, msg_tag)) => (peer_eid, msg_tag),
                    Err(e) => {
                        println!("[MCTP-CAPSULE]: parse_args failed");
                        return CommandReturn::failure(e);
                    }
                };

                if command_num == 1 {
                    self.apps
                        .enter(process_id, |app, _| {
                            let req_rx_ctx = OpContext {
                                msg_tag,
                                peer_eid,
                                op_type: OpType::Rx,
                            };
                            app.pending_rx_request = Some(req_rx_ctx);
                            // Check if we have a buffered message that matches this request
                            if self.check_buffered_message(&req_rx_ctx) {
                                self.deferred_call.set();
                            }
                            CommandReturn::success()
                        })
                        .unwrap_or_else(|err| CommandReturn::failure(err.into()))
                } else if command_num == 2 {
                    self.apps
                        .enter(process_id, |app, _| {
                            let rsp_rx_ctx = OpContext {
                                msg_tag,
                                peer_eid,
                                op_type: OpType::Rx,
                            };
                            // Check if we have a buffered message that matches this response
                            if self.check_buffered_message(&rsp_rx_ctx) {
                                self.deferred_call.set();
                            }
                            app.pending_rx_response = Some(rsp_rx_ctx);
                            CommandReturn::success()
                        })
                        .unwrap_or_else(|err| CommandReturn::failure(err.into()))
                } else {
                    CommandReturn::failure(ErrorCode::NOSUPPORT)
                }
            }
            // 3. Send Request Message
            // 4: Send Response Message
            3 | 4 => {
                let (peer_eid, msg_tag) = match self.parse_args(command_num, arg1, arg2) {
                    Ok((peer_eid, msg_tag)) => (peer_eid, msg_tag),
                    Err(e) => {
                        println!("[MCTP-CAPSULE]: parse_args failed");
                        return CommandReturn::failure(e);
                    }
                };
                let result = self
                    .apps
                    .enter(process_id, |app, kernel_data| {
                        if app.pending_tx.is_some() {
                            return Err(ErrorCode::BUSY);
                        }

                        self.send_msg_payload(process_id, app, kernel_data, peer_eid, msg_tag)
                    })
                    .unwrap_or_else(|err| Err(err.into()));

                match result {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }
            5 => CommandReturn::success_u32(self.max_msg_size as u32),
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(process_id, |_, _| {})
    }
}

impl MCTPTxClient for MCTPDriver<'_> {
    fn send_done(
        &self,
        dest_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        result: Result<(), ErrorCode>,
        mut msg_payload: SubSliceMut<'static, u8>,
    ) {
        msg_payload.reset();
        self.kernel_msg_buf.replace(msg_payload);

        if self.msg_type as u8 != msg_type {
            panic!(
                "[MCTP-CAPSULE]::send_done received for msg_type {} that does not match driver msg type {}",
                msg_type, self.msg_type as u8
            );
        }

        let process_id = match self.current_app.get() {
            Some(process_id) => process_id,
            None => {
                println!("[MCTP-CAPSULE]::send_done no app waiting for send_done");
                return;
            }
        };

        _ = self.apps.enter(process_id, |app, up_calls| {
            // Check if the send operation matches the pending tx operation
            if !self.tx_pending(app, msg_tag, dest_eid) {
                println!("[MCTP-CAPSULE]::send_done no pending tx operation");
                return;
            }

            app.pending_tx = None;
            let msg_info = ((msg_type as usize) << 8) | ((msg_tag & MCTP_TAG_MASK) as usize);
            up_calls
                .schedule_upcall(
                    upcall::MESSAGE_TRANSMITTED,
                    (
                        kernel::errorcode::into_statuscode(result),
                        dest_eid as usize,
                        msg_info,
                    ),
                )
                .ok();
        });
        self.current_app.set(None);
    }
}

impl MCTPRxClient for MCTPDriver<'_> {
    fn receive(
        &self,
        src_eid: u8,
        msg_type: u8,
        msg_tag: u8,
        msg_payload: &[u8],
        msg_len: usize,
        recv_time: u32,
    ) {
        if self.msg_type as u8 != msg_type {
            panic!(
                "[MCTP-CAPSULE]::receive received for msg_type {} that does not match driver msg type {}",
                msg_type, self.msg_type as u8
            );
        }

        let mut rx_upcall_scheduled = false;

        self.apps.each(|_, app, kernel_data| {
            if rx_upcall_scheduled {
                return;
            }

            // Determine which operation matches the received message
            let is_request = if self.pending_rx_request(app, msg_tag, src_eid) {
                true
            } else if self.pending_rx_response(app, msg_tag, src_eid) {
                false
            } else {
                return; // No matching pending operation for this app
            };

            let rw_buffer = if is_request {
                rw_allow::READ_REQUEST
            } else {
                rw_allow::READ_RESPONSE
            };

            // Copy the message payload to the process buffer
            let res = kernel_data
                .get_readwrite_processbuffer(rw_buffer)
                .and_then(|read| {
                    read.mut_enter(|rmsg_payload| {
                        if rmsg_payload.len() < msg_len {
                            Err(ErrorCode::SIZE)
                        } else {
                            rmsg_payload[..msg_len].copy_from_slice(&msg_payload[..msg_len]);
                            Ok(())
                        }
                    })
                })
                .unwrap_or(Err(ErrorCode::NOMEM));

            // Schedule the upcall if the message payload is copied successfully
            if res.is_ok() {
                let subscribe_num = if is_request {
                    app.pending_rx_request = None;
                    upcall::RECEIVED_REQUEST
                } else {
                    app.pending_rx_response = None;
                    upcall::RECEIVED_RESPONSE
                };

                let msg_info =
                    ((src_eid as usize) << 16) | ((msg_type as usize) << 8) | (msg_tag as usize);
                if let Err(e) = kernel_data
                    .schedule_upcall(subscribe_num, (msg_len, recv_time as usize, msg_info))
                {
                    println!("[MCTP-CAPSULE]::receive upcall schedule failed: {:?}", e);
                } else {
                    rx_upcall_scheduled = true;
                }
            }
        });

        // If no application was waiting for this message at the moment, buffer it
        if !rx_upcall_scheduled {
            if self.buffer_message(src_eid, msg_type, msg_tag, msg_payload, msg_len, recv_time) {
            } else {
                println!("[MCTP-CAPSULE]::receive no pending rx operation and buffering failed - dropping message");
            }
        }
    }
}

impl DeferredCallClient for MCTPDriver<'_> {
    fn handle_deferred_call(&self) {
        self.deliver_buffered_message();
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}
