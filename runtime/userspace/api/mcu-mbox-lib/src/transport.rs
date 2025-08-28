// Licensed under the Apache-2.0 license

use core::mem::size_of;
use libsyscall_caliptra::mcu_mbox::{CmdCode, MbxCmdStatus, McuMbox, MCU_MBOX0_DRIVER_NUM};
use mcu_mbox_common::{verify_checksum, MailboxReqHeader, MailboxRespHeader, McuMboxError};
use zerocopy::{FromBytes, IntoBytes};

// debug usage remove later
use core::fmt::Write;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;

#[derive(Debug)]
pub enum TransportError {
    //DriverError,
    BufferTooSmall,
    DriverRxError,
    DriverTxError,
    InvalidRequest,
    ChkSumMismatch,
}

pub struct McuMboxTransport {
    mbox: McuMbox,
}

impl McuMboxTransport {
    pub fn new(drv_num: u32) -> Self {
        Self {
            mbox: McuMbox::new(drv_num),
        }
    }

    pub async fn receive_request(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(CmdCode, usize), TransportError> {
        let mut console_writer = Console::<DefaultSyscalls>::writer();

        // Check buffer length before syscall
        if buf.len() < size_of::<MailboxReqHeader>() {
            return Err(TransportError::BufferTooSmall);
        }

        // Reset buffer
        buf.fill(0);

        // Receive request from MCU mailbox
        let (cmd_opcode, req_len) = self
            .mbox
            .receive_command(buf)
            .await
            .map_err(|_| TransportError::DriverRxError)?;

        writeln!(
            console_writer,
            "[xs debug]Mbox transport receive request: cmd_opcode: {:?}, req_len={:?}",
            cmd_opcode, req_len
        )
        .unwrap();
        // Check request buffer length after receive
        if req_len < size_of::<MailboxReqHeader>() {
            return Err(TransportError::InvalidRequest);
        }

        // Verify request checksum against cmd_opcode and payload
        let hdr: &MailboxReqHeader =
            MailboxReqHeader::ref_from_bytes(&buf[..size_of::<MailboxReqHeader>()])
                .map_err(|_| TransportError::InvalidRequest)?;

        if !verify_checksum(
            hdr.chksum,
            cmd_opcode,
            &buf[core::mem::size_of_val(&hdr.chksum)..req_len],
        ) {
            writeln!(console_writer, "[xs debug]receive request: Chksum mismatch").unwrap();
            return Err(TransportError::ChkSumMismatch);
        }

        Ok((cmd_opcode, req_len))
    }

    pub async fn send_response(
        &mut self,
        resp: &[u8],
        status: MbxCmdStatus,
    ) -> Result<(), TransportError> {
        // Check response buffer length before syscall
        if resp.len() < size_of::<MailboxRespHeader>() {
            return Err(TransportError::BufferTooSmall);
        }

        // Send response to MCU mailbox
        self.mbox
            .send_response(resp, status)
            .await
            .map_err(|_| TransportError::DriverTxError)?;

        Ok(())
    }
}
