// Licensed under the Apache-2.0 license

use crate::errors;
use caliptra_mcu_libsyscall_caliptra::mci::Mci;
use caliptra_mcu_libsyscall_caliptra::mcu_mbox::{CmdCode, MbxCmdStatus, McuMbox};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_mbox_common::messages::{verify_checksum, MailboxReqHeader, MailboxRespHeader};
use core::mem::size_of;
use mcu_error::McuResult;
use zerocopy::FromBytes;

/// MCU Mailbox Transport implementation using the McuMbox syscall interface.
pub struct McuMboxTransport {
    mbox: McuMbox,
    ready_signaled: bool,
}

impl McuMboxTransport {
    pub fn new(drv_num: u32) -> Self {
        Self {
            mbox: McuMbox::new(drv_num),
            ready_signaled: false,
        }
    }

    pub async fn receive_request<'a>(
        &mut self,
        buf: &'a mut [u8],
    ) -> McuResult<(CmdCode, u32, &'a [u8])> {
        if buf.len() < size_of::<MailboxReqHeader>() {
            return Err(errors::BUFFER_TOO_SMALL);
        }

        buf.fill(0);

        let on_listening_cb = if !self.ready_signaled {
            self.ready_signaled = true;
            Some(|| {
                let mci = Mci::<DefaultSyscalls>::new();
                mci.set_mailbox_ready().unwrap();
            })
        } else {
            None
        };

        let (cmd_opcode, req_len, axi_user) = self
            .mbox
            .receive_command(buf, on_listening_cb)
            .await
            .map_err(|_| errors::DRIVER_RX_ERROR)?;

        if req_len < size_of::<MailboxReqHeader>() {
            return Err(errors::INVALID_REQUEST);
        }

        let hdr = MailboxReqHeader::ref_from_bytes(
            buf.get(..size_of::<MailboxReqHeader>())
                .ok_or(errors::INVALID_REQUEST)?,
        )
        .map_err(|_| errors::INVALID_REQUEST)?;
        // Retrieve payload for checksum verification
        let payload = buf
            .get(size_of::<u32>()..req_len)
            .ok_or(errors::INVALID_REQUEST)?;
        if !verify_checksum(hdr.chksum, cmd_opcode, payload) {
            return Err(errors::CHKSUM_MISMATCH);
        }

        Ok((
            cmd_opcode,
            axi_user,
            buf.get(..req_len).ok_or(errors::INVALID_REQUEST)?,
        ))
    }

    pub async fn send_response(&mut self, resp: &[u8]) -> McuResult<()> {
        if resp.len() < size_of::<MailboxRespHeader>() {
            return Err(errors::BUFFER_TOO_SMALL);
        }

        let hdr = MailboxRespHeader::ref_from_bytes(
            resp.get(..size_of::<MailboxRespHeader>())
                .ok_or(errors::INVALID_RESPONSE)?,
        )
        .map_err(|_| errors::INVALID_RESPONSE)?;
        let payload = resp
            .get(size_of::<u32>()..)
            .ok_or(errors::INVALID_RESPONSE)?;
        if !verify_checksum(hdr.chksum, 0, payload) {
            return Err(errors::CHKSUM_MISMATCH);
        }

        self.mbox
            .send_response(resp)
            .await
            .map_err(|_| errors::DRIVER_TX_ERROR)?;

        Ok(())
    }

    pub fn finalize_response(&self, status: MbxCmdStatus) -> McuResult<()> {
        self.mbox
            .finish_response(status)
            .map_err(|_| errors::DRIVER_TX_ERROR)
    }

    pub fn is_pl0_axi_user(&self, axi_user: u32) -> bool {
        self.mbox.is_pl0_axi_user(axi_user).unwrap_or(false)
    }
}
