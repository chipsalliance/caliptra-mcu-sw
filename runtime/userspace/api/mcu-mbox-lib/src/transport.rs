// Licensed under the Apache-2.0 license

use core::mem::size_of;
use libsyscall_caliptra::mcu_mbox::{CmdCode, MbxCmdStatus, McuMbox};
use mcu_mbox_common::messages::{verify_checksum, MailboxReqHeader, MailboxRespHeader};
use zerocopy::FromBytes;

pub enum TransportError {
    DriverRxError,
    DriverTxError,
    BufferTooSmall,
    InvalidRequest,
    InvalidResponse,
    ChkSumMismatch,
}

/// MCU Mailbox Transport implementation using the McuMbox syscall interface.
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
        if buf.len() < size_of::<MailboxReqHeader>() {
            return Err(TransportError::BufferTooSmall);
        }

        buf.fill(0);

        let (cmd_opcode, req_len) = self
            .mbox
            .receive_command(buf)
            .await
            .map_err(|_| TransportError::DriverRxError)?;

        if req_len < size_of::<MailboxReqHeader>() {
            return Err(TransportError::InvalidRequest);
        }

        let hdr = MailboxReqHeader::ref_from_bytes(&buf[..size_of::<MailboxReqHeader>()])
            .map_err(|_| TransportError::InvalidRequest)?;
        // Retrieve payload for checksum verification
        let payload = &buf[size_of::<u32>()..req_len];
        if !verify_checksum(hdr.chksum, cmd_opcode, payload) {
            return Err(TransportError::ChkSumMismatch);
        }

        Ok((cmd_opcode, req_len))
    }

    pub async fn send_response(&mut self, resp: &[u8]) -> Result<(), TransportError> {
        if resp.len() < size_of::<MailboxRespHeader>() {
            return Err(TransportError::BufferTooSmall);
        }

        let hdr = MailboxRespHeader::ref_from_bytes(&resp[..size_of::<MailboxRespHeader>()])
            .map_err(|_| TransportError::InvalidResponse)?;
        let payload = &resp[size_of::<u32>()..];
        if !verify_checksum(hdr.chksum, 0, payload) {
            return Err(TransportError::ChkSumMismatch);
        }

        self.mbox
            .send_response(resp)
            .await
            .map_err(|_| TransportError::DriverTxError)?;

        Ok(())
    }

    pub fn finalize_response(&self, status: MbxCmdStatus) -> Result<(), TransportError> {
        self.mbox
            .finish_response(status)
            .map_err(|_| TransportError::DriverTxError)
    }
}
