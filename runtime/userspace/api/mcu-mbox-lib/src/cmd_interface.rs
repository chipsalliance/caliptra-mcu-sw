// Licensed under the Apache-2.0 license

use crate::error::MsgHandlerError;
use crate::transport::McuMboxTransport;
use core::sync::atomic::{AtomicBool, Ordering};
use external_cmds_common::{FirmwareVersion, UnifiedCommandHandler};
use libsyscall_caliptra::mcu_mbox::MbxCmdStatus;
use mcu_mbox_common::{
    CommandId, FirmwareVersionReq, FirmwareVersionResp, MailboxRespHeader, McuMailboxResp,
};
use zerocopy::{FromBytes, IntoBytes};

pub struct CmdInterface<'a> {
    transport: &'a mut McuMboxTransport, // Mcu mailbox transport interface
    non_crypto_cmds_handler: &'a dyn UnifiedCommandHandler,
    busy: AtomicBool,
}

impl<'a> CmdInterface<'a> {
    pub fn new(
        transport: &'a mut McuMboxTransport,
        non_crypto_cmds_handler: &'a dyn UnifiedCommandHandler,
    ) -> Self {
        Self {
            transport,
            non_crypto_cmds_handler,
            busy: AtomicBool::new(false),
        }
    }

    pub async fn handle_responder_msg(
        &mut self,
        msg_buf: &mut [u8],
    ) -> Result<(), MsgHandlerError> {
        // Receive command ID and request payload from transport layer
        let (cmd_id, req_len) = self
            .transport
            .receive_request(msg_buf)
            .await
            .map_err(|_| MsgHandlerError::Transport)?;

        // Process the request
        let (resp_len, status) = self.process_request(msg_buf, cmd_id, req_len).await?;

        // Send the response back
        self.transport
            .send_response(&msg_buf[..resp_len], status)
            .await
            .map_err(|_| MsgHandlerError::Transport)?;

        Ok(())
    }

    async fn process_request(
        &mut self,
        msg_buf: &mut [u8],
        cmd: u32,
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        if self.busy.load(Ordering::SeqCst) {
            return Err(MsgHandlerError::NotReady);
        }

        self.busy.store(true, Ordering::SeqCst);

        // Parse the request payload
        let result = match CommandId::from(cmd) {
            // Command ID is firmware version
            CommandId::MC_FIRMWARE_VERSION => self.handle_fw_version(msg_buf, req_len).await,
            // Add more command handlers
            _ => Err(MsgHandlerError::UnsupportedCommand),
        };

        self.busy.store(false, Ordering::SeqCst);

        result
    }

    async fn handle_fw_version(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        // Parse the request
        let req: &FirmwareVersionReq = FirmwareVersionReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        let index = req.index;
        let mut version = FirmwareVersion::default();

        // Process the firmware version command
        let ret = self
            .non_crypto_cmds_handler
            .get_firmware_version(index, &mut version)
            .await;

        let mbox_cmd_status = if ret.is_err() {
            MbxCmdStatus::Failure
        } else {
            MbxCmdStatus::Complete
        };

        // Here we just create a dummy response for illustration
        let mut resp = McuMailboxResp::FirmwareVersion(FirmwareVersionResp {
            hdr: MailboxRespHeader::default(),
            version: { version.0 },
        });

        // Populate checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode resp into msg_buffer
        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), mbox_cmd_status))
    }
}
