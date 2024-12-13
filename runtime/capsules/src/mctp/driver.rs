// Licensed under the Apache-2.0 license

use crate::mctp::recv::MCTPRxClient;
use crate::mctp::send::{MCTPSender, MCTPTxClient};

use crate::mctp::common::*;

use core::cell::Cell;

use kernel::debug;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::WriteableProcessBuffer;
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::MapCell;
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::{ErrorCode, ProcessId};

pub const MAX_MESSAGE_TYPES: usize = 2;

pub const SPDM_MAX_MESSAGE_SIZE: usize = 4098;
pub const PLDM_MAX_MESSAGE_SIZE: usize = 4098;
pub const VENDOR_DEFINED_PCI_MAX_MESSAGE_SIZE: usize = 4098;

pub const MCTP_SPDM_DRIVER_NUM: usize = 0xA0000;
pub const MCTP_PLDM_DRIVER_NUM: usize = 0xA0001;
pub const MCTP_VENDOR_DEFINED_PCI_DRIVER_NUM: usize = 0xA0002;

/// IDs for subscribe calls
mod upcall {
    /// Callback for when the message is received
    pub const MESSAGE_RECEIVED: usize = 0;

    /// Callback for when the message is transmitted.
    pub const MESSAGE_TRANSMITTED: usize = 1;

    /// Number of upcalls
    pub const COUNT: u8 = 2;
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
    pub const MESSAGE_READ: usize = 0;

    /// Number of read-write allow buffers
    pub const COUNT: u8 = 1;
}

enum OpType {
    SendReq,
    SendResp,
    ReceiveReq,
    ReceiveResp,
    Idle,
}

struct OpContext {
    msg_tag: u8,
    peer_eid: u8,
    msg_type: u8,
    op_type: OpType,
}

impl OpContext {
    fn is_match(&self, msg_tag: u8, peer_eid: u8, msg_type: u8) -> bool {
        if self.msg_type != msg_type {
            return false;
        }
        match self.op_type {
            OpType::ReceiveReq => {
                if msg_tag & MCTP_TAG_OWNER != 0 {
                    return true;
                }
            }
            OpType::ReceiveResp => {
                if self.msg_tag & MCTP_TAG_MASK == msg_tag && self.peer_eid == peer_eid {
                    return true;
                }
            }
            _ => {}
        }
        false
    }
}

#[derive(Default)]
pub struct App {
    pending_op_ctx: Option<OpContext>,
    pending_tx: Option<OpContext>,
}

pub struct MCTPDriver<'a> {
    sender: &'a dyn MCTPSender,
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    app_id: Cell<Option<ProcessId>>,
    msg_types: [u8; MAX_MESSAGE_TYPES],
    max_msg_size: usize,
    kernel_msg_buf: MapCell<SubSliceMut<'static, u8>>,
}

impl<'a> MCTPDriver<'a> {
    pub fn new(
        sender: &'a dyn MCTPSender,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        msg_types: [u8; MAX_MESSAGE_TYPES],
        max_msg_size: usize,
        msg_buf: SubSliceMut<'static, u8>,
    ) -> MCTPDriver<'a> {
        MCTPDriver {
            sender,
            apps: grant,
            app_id: Cell::new(None),
            msg_types,
            max_msg_size,
            kernel_msg_buf: MapCell::new(msg_buf),
        }
    }

    fn supported_msg_type(&self, msg_type: u8) -> bool {
        for i in 0..MAX_MESSAGE_TYPES {
            if msg_type == self.msg_types[i] {
                return true;
            }
        }
        false
    }
}

impl<'a> SyscallDriver for MCTPDriver<'a> {
    fn command(
        &self,
        command_num: usize,
        arg1: usize,
        arg2: usize,
        process_id: ProcessId,
    ) -> CommandReturn {

        // lower 8 bits of arg2 is always msg_type
        let msg_type = arg2 as u8;
        if !self.supported_msg_type(msg_type) {
            return CommandReturn::failure(ErrorCode::INVAL);
        }

        match command_num {
            0 => CommandReturn::success(),
            // Receive Request Message
            // arg1: peer_eid
            // arg2: msg_type
            1 => self
                .apps
                .enter(process_id, |app, _| {
                    app.pending_op_ctx = Some(OpContext {
                        msg_tag: MCTP_TAG_OWNER,
                        peer_eid: arg1 as u8,
                        msg_type: msg_type,
                        op_type: OpType::ReceiveReq,
                    });
                    CommandReturn::success()
                })
                .unwrap_or_else(|err| CommandReturn::failure(err.into())),
            // Receive Response Message
            // arg1: peer_eid
            // arg2: msg_tag << 8 | msg_type
            2 => self
                .apps
                .enter(process_id, |app, _| {
                    let peer_eid = arg1 as u8;
                    let msg_tag = ((arg2 >> 8) & 0xFF) as u8;

                    app.pending_op_ctx = Some(OpContext {
                        msg_tag,
                        peer_eid,
                        msg_type,
                        op_type: OpType::ReceiveResp,
                    });
                    CommandReturn::success()
                })
                .unwrap_or_else(|err| CommandReturn::failure(err.into())),
            // Send Request Message
            // arg1: dest_eid
            // arg2: msg_type
            3 => {
                let result = self.apps.enter(process_id, |app, kernel_data| {
                    let dest_eid = arg1 as u8;

                    if app.pending_tx.is_some() {
                        return Err(ErrorCode::BUSY);
                    }

                    // copy the app buffer into kernel buffer
                    kernel_data
                        .get_readonly_processbuffer(ro_allow::MESSAGE_WRITE)
                        .and_then(|write| {
                            write.enter(|wmsg_payload| {
                                let mut msg_buf = self.kernel_msg_buf.take();
                                match msg_buf {
                                    Some(msg_buf) => {
                                        if wmsg_payload.len() > msg_buf.len() {
                                            return Err(ErrorCode::SIZE);
                                        }
                                        msg_buf[..wmsg_payload.len()].copy_from_slice(wmsg_payload);
                                        self.kernel_msg_buf.replace(msg_buf);
                                        Ok(())
                                    }
                                    None => Err(ErrorCode::NOMEM),
                                }
                            })
                        })
                        .unwrap_or_else(|err| Err(err.into()))?;
                    

                    

                    

                }).unwrap_or_else(|err| Err(err.into()));
                match result {
                    Ok(_) => {
                        debug!("MCTPDriver::command: 3. Send Request Message");
                        CommandReturn::success()
                    }
                    Err(e) => CommandReturn::failure(e),
                }
            4 => {
                debug!("MCTPDriver::command: 4. TODO Send Response Message");
                CommandReturn::success()
            }
            5 => CommandReturn::success_u32(self.max_msg_size as u32),
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(process_id, |_, _| {})
    }
}

impl<'a> MCTPTxClient for MCTPDriver<'a> {
    fn send_done(
        &self,
        msg_tag: Option<u8>,
        result: Result<(), ErrorCode>,
        msg_payload: SubSliceMut<'static, u8>,
    ) {
        debug!("MCTPDriver::send_done: {:?}", result);
    }
}

impl<'a> MCTPRxClient for MCTPDriver<'a> {
    fn receive(&self, src_eid: u8, msg_type: u8, msg_tag: u8, msg_payload: &[u8], msg_len: usize) {
        self.apps.each(|_, app, kernel_data| {
            if let Some(op_ctx) = app.pending_op_ctx.as_mut() {
                if op_ctx.is_match(msg_tag, src_eid, msg_type) {
                    let res = kernel_data
                        .get_readwrite_processbuffer(rw_allow::MESSAGE_READ)
                        .and_then(|read| {
                            read.mut_enter(|rmsg_payload| {
                                if rmsg_payload.len() < msg_len {
                                    Err(ErrorCode::SIZE)
                                } else {
                                    rmsg_payload[..msg_len].copy_from_slice(msg_payload);
                                    Ok(())
                                }
                            })
                        })
                        .unwrap_or(Ok(()));

                    if res.is_ok() {
                        app.pending_op_ctx = None;
                        let msg_info = msg_type << 8 | msg_tag;
                        kernel_data
                            .schedule_upcall(
                                upcall::MESSAGE_RECEIVED,
                                (msg_len, src_eid as usize, msg_info as usize),
                            )
                            .ok();
                    }
                }
            }
        });
    }
}
