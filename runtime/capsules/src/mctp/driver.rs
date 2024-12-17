// Licensed under the Apache-2.0 license

use crate::mctp::base_protocol::*;
use crate::mctp::recv::MCTPRxClient;
use crate::mctp::send::{MCTPSender, MCTPTxClient};

use core::cell::Cell;
use core::fmt::Write;
use romtime::println;

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::MapCell;
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::{ErrorCode, ProcessId};

pub const MCTP_MAX_MESSAGE_SIZE: usize = 4098;

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
    Tx,
    Rx,
}

struct OpContext {
    msg_tag: u8,
    peer_eid: u8,
    msg_type: u8,
    op_type: OpType,
}

impl OpContext {
    fn for_me(&self, msg_tag: u8, peer_eid: u8, msg_type: u8) -> bool {
        if self.msg_type != msg_type {
            return false;
        }
        match self.op_type {
            OpType::Rx => {
                if self.msg_tag == msg_tag {
                    if msg_tag & MCTP_TAG_OWNER != 0 {
                        return true;
                    }
                    if self.peer_eid == peer_eid {
                        return true;
                    }
                }
            }
            OpType::Tx => {
                if self.peer_eid == peer_eid {
                    if msg_tag & MCTP_TAG_OWNER != 0 {
                        return true;
                    }
                    if self.msg_tag == msg_tag {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[derive(Default)]
pub struct App {
    pending_rx: Option<OpContext>,
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
    msg_types: &'static [u8],
    max_msg_size: usize,
    kernel_msg_buf: MapCell<SubSliceMut<'static, u8>>,
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
        msg_types: &'static [u8],
        max_msg_size: usize,
        msg_buf: SubSliceMut<'static, u8>,
    ) -> MCTPDriver<'a> {
        MCTPDriver {
            sender,
            apps: grant,
            current_app: Cell::new(None),
            msg_types,
            max_msg_size,
            kernel_msg_buf: MapCell::new(msg_buf),
        }
    }

    fn supported_msg_type(&self, msg_type: u8) -> bool {
        self.msg_types.iter().any(|&t| t == msg_type)
    }

    fn validate_args(
        &self,
        command_num: usize,
        arg1: usize,
        arg2: usize,
    ) -> Result<(u8, u8, u8), ErrorCode> {
        // arg1 is always peer_eid
        let peer_eid = arg1 as u8;

        if !valid_eid(peer_eid) {
            Err(ErrorCode::INVAL)?;
        }

        // lower 8 bits of arg2 is always msg_type
        let msg_type = (arg2 & 0xFF) as u8;
        if !self.supported_msg_type(msg_type) {
            Err(ErrorCode::INVAL)?;
        }
        let msg_tag = (arg2 >> 8 & 0xFF) as u8;

        // Receive Request message or send Request message
        if ((command_num == 1 || command_num == 3) && msg_tag != MCTP_TAG_OWNER)
            || ((command_num == 2 || command_num == 4) && msg_tag & MCTP_TAG_OWNER != 0)
        {
            Err(ErrorCode::INVAL)?;
        }

        Ok((peer_eid, msg_type, msg_tag))
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
        let (peer_eid, msg_type, msg_tag) = match self.validate_args(command_num, arg1, arg2) {
            Ok((peer_eid, msg_type, msg_tag)) => (peer_eid, msg_type, msg_tag),
            Err(e) => return CommandReturn::failure(e),
        };

        match command_num {
            0 => CommandReturn::success(),
            // 1: Receive Request Message
            // 2: Receive Response Message
            1 | 2 => self
                .apps
                .enter(process_id, |app, _| {
                    app.pending_rx = Some(OpContext {
                        msg_tag,
                        peer_eid,
                        msg_type,
                        op_type: OpType::Rx,
                    });
                    CommandReturn::success()
                })
                .unwrap_or_else(|err| CommandReturn::failure(err.into())),
            // 3. Send Request Message
            // 4: Send Response Message
            3 | 4 => {
                let result = self
                    .apps
                    .enter(process_id, |app, kernel_data| {
                        let dest_eid = arg1 as u8;
                        if app.pending_tx.is_some() {
                            return Err(ErrorCode::BUSY);
                        }

                        let res = kernel_data
                            .get_readonly_processbuffer(ro_allow::MESSAGE_WRITE)
                            .and_then(|write| {
                                write.enter(|wpayload| {
                                    self.kernel_msg_buf.take().map_or(
                                        Err(ErrorCode::NOMEM),
                                        |mut kernel_msg_buf| {
                                            if wpayload.len() > kernel_msg_buf.len() {
                                                return Err(ErrorCode::SIZE);
                                            }
                                            wpayload.copy_to_slice(
                                                &mut kernel_msg_buf[..wpayload.len()],
                                            );
                                            kernel_msg_buf.slice(0..wpayload.len());

                                            match self.sender.send_msg(
                                                msg_type,
                                                dest_eid,
                                                msg_tag,
                                                kernel_msg_buf,
                                            ) {
                                                Ok(_) => {
                                                    println!("MCTPDriver: send_msg success");
                                                    app.pending_tx = Some(OpContext {
                                                        msg_tag,
                                                        peer_eid: dest_eid,
                                                        msg_type,
                                                        op_type: OpType::Tx,
                                                    });
                                                    self.current_app.set(Some(process_id));
                                                    Ok(())
                                                }
                                                Err(mut buf) => {
                                                    println!("MCTPDriver: send_msg failed");
                                                    buf.reset();
                                                    self.kernel_msg_buf.replace(buf);
                                                    Err(ErrorCode::FAIL)
                                                }
                                            }
                                        },
                                    )
                                })
                            })
                            .unwrap_or(Err(ErrorCode::FAIL));
                        match res {
                            Ok(()) => Ok(()),
                            Err(e) => Err(e),
                        }
                        // Ok(())
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

impl<'a> MCTPTxClient for MCTPDriver<'a> {
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
        if let Some(process_id) = self.current_app.get() {
            _ = self.apps.enter(process_id, |app, up_calls| {
                if let Some(op_ctx) = app.pending_tx.as_mut() {
                    if op_ctx.for_me(msg_tag, dest_eid, msg_type) {
                        app.pending_tx = None;
                        let msg_info = (msg_type as usize) << 8 | (msg_tag as usize);
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
                    }
                }
            });
        }
        self.current_app.set(None);
    }
}

impl<'a> MCTPRxClient for MCTPDriver<'a> {
    fn receive(&self, src_eid: u8, msg_type: u8, msg_tag: u8, msg_payload: &[u8], msg_len: usize) {
        self.apps.each(|_, app, kernel_data| {
            if let Some(op_ctx) = app.pending_rx.as_mut() {
                if op_ctx.for_me(msg_tag, src_eid, msg_type) {
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
                        app.pending_rx = None;
                        let msg_info = (msg_type as usize) << 8 | (msg_tag as usize);
                        kernel_data
                            .schedule_upcall(
                                upcall::MESSAGE_RECEIVED,
                                (msg_len, src_eid as usize, msg_info),
                            )
                            .ok();
                    }
                }
            }
        });
    }
}
