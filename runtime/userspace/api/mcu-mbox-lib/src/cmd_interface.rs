// Licensed under the Apache-2.0 license

use crate::transport::McuMboxTransport;
use caliptra_api::mailbox::{CommandId as CaliptraCommandId, MailboxReqHeader};
use core::sync::atomic::{AtomicBool, Ordering};
use external_cmds_common::{
    DeviceCapabilities, DeviceId, DeviceInfo, FirmwareVersion, UnifiedCommandHandler, MAX_UID_LEN,
};
use libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use libsyscall_caliptra::mailbox::Mailbox;
use libsyscall_caliptra::mcu_mbox::MbxCmdStatus;
use mcu_mbox_common::messages::{
    CommandId, DeviceCapsReq, DeviceCapsResp, DeviceIdReq, DeviceIdResp, DeviceInfoReq,
    DeviceInfoResp, FirmwareVersionReq, FirmwareVersionResp, MailboxRespHeader,
    MailboxRespHeaderVarSize, McuAesDecryptInitReq, McuAesDecryptInitResp, McuAesDecryptUpdateReq,
    McuAesDecryptUpdateResp, McuAesEncryptInitReq, McuAesEncryptInitResp, McuAesEncryptUpdateReq,
    McuAesEncryptUpdateResp, McuAesGcmDecryptFinalReq, McuAesGcmDecryptFinalResp,
    McuAesGcmDecryptInitReq, McuAesGcmDecryptInitResp, McuAesGcmDecryptUpdateReq,
    McuAesGcmDecryptUpdateResp, McuAesGcmEncryptFinalReq, McuAesGcmEncryptFinalResp,
    McuAesGcmEncryptInitReq, McuAesGcmEncryptInitResp, McuAesGcmEncryptUpdateReq,
    McuAesGcmEncryptUpdateResp, McuCmDeleteReq, McuCmDeleteResp, McuCmImportReq, McuCmImportResp,
    McuCmStatusReq, McuCmStatusResp, McuMailboxResp, McuRandomGenerateReq, McuRandomGenerateResp,
    McuRandomStirReq, McuRandomStirResp, McuShaFinalReq, McuShaFinalResp, McuShaInitReq,
    McuShaInitResp, McuShaUpdateReq, DEVICE_CAPS_SIZE, MAX_FW_VERSION_STR_LEN,
};
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug)]
pub enum MsgHandlerError {
    Transport,
    McuMboxCommon,
    NotReady,
    InvalidParams,
    UnsupportedCommand,
}

/// Command interface for handling MCU mailbox commands.
pub struct CmdInterface<'a> {
    transport: &'a mut McuMboxTransport,
    non_crypto_cmds_handler: &'a dyn UnifiedCommandHandler,
    caliptra_mbox: libsyscall_caliptra::mailbox::Mailbox, // Handle crypto commands via caliptra mailbox
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
            caliptra_mbox: Mailbox::new(),
            busy: AtomicBool::new(false),
        }
    }

    pub async fn handle_responder_msg(
        &mut self,
        msg_buf: &mut [u8],
    ) -> Result<(), MsgHandlerError> {
        // Receive a request from the transport.
        let (cmd_id, req_len) = self
            .transport
            .receive_request(msg_buf)
            .await
            .map_err(|_| MsgHandlerError::Transport)?;

        // Process the request and prepare the response.
        let (resp_len, status) = self.process_request(msg_buf, cmd_id, req_len).await?;

        // Send the response if the command completed successfully.
        if status == MbxCmdStatus::Complete {
            self.transport
                .send_response(&msg_buf[..resp_len])
                .await
                .map_err(|_| MsgHandlerError::Transport)?;
        }

        // Finalize the response as the last step of handling the message.
        self.transport
            .finalize_response(status)
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

        let result = match CommandId::from(cmd) {
            CommandId::MC_FIRMWARE_VERSION => self.handle_fw_version(msg_buf, req_len).await,
            CommandId::MC_DEVICE_CAPABILITIES => self.handle_device_caps(msg_buf, req_len).await,
            CommandId::MC_DEVICE_ID => self.handle_device_id(msg_buf, req_len).await,
            CommandId::MC_DEVICE_INFO => self.handle_device_info(msg_buf, req_len).await,
            CommandId::MC_SHA_INIT => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuShaInitResp>()];
                self.handle_crypto_passthrough::<McuShaInitReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_SHA_INIT.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_SHA_UPDATE => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuShaInitResp>()];
                self.handle_crypto_passthrough::<McuShaUpdateReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_SHA_UPDATE.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_SHA_FINAL => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuShaFinalResp>()];
                self.handle_crypto_passthrough::<McuShaFinalReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_SHA_FINAL.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_IMPORT => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuCmImportResp>()];
                self.handle_crypto_passthrough::<McuCmImportReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_IMPORT.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_DELETE => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuCmDeleteResp>()];
                self.handle_crypto_passthrough::<McuCmDeleteReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_DELETE.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_CM_STATUS => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuCmStatusResp>()];
                self.handle_crypto_passthrough::<McuCmStatusReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_STATUS.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_RANDOM_GENERATE => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuRandomGenerateResp>()];
                self.handle_crypto_passthrough::<McuRandomGenerateReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_RANDOM_GENERATE.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_RANDOM_STIR => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuRandomStirResp>()];
                self.handle_crypto_passthrough::<McuRandomStirReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_RANDOM_STIR.into(),
                    &mut resp_bytes,
                )
                .await
            }
            // Add AES Encrypt commands
            CommandId::MC_AES_ENCRYPT_INIT => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuAesEncryptInitResp>()];
                self.handle_crypto_passthrough::<McuAesEncryptInitReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_AES_ENCRYPT_INIT.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_AES_ENCRYPT_UPDATE => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuAesEncryptUpdateResp>()];
                self.handle_crypto_passthrough::<McuAesEncryptUpdateReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_AES_ENCRYPT_UPDATE.into(),
                    &mut resp_bytes,
                )
                .await
            }
            // Add AES Decrypt commands
            CommandId::MC_AES_DECRYPT_INIT => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuAesDecryptInitResp>()];
                self.handle_crypto_passthrough::<McuAesDecryptInitReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_AES_DECRYPT_INIT.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_AES_DECRYPT_UPDATE => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuAesDecryptUpdateResp>()];
                self.handle_crypto_passthrough::<McuAesDecryptUpdateReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_AES_DECRYPT_UPDATE.into(),
                    &mut resp_bytes,
                )
                .await
            }
            // Add AES GCM encrypt commands here.
            CommandId::MC_AES_GCM_ENCRYPT_INIT => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuAesGcmEncryptInitResp>()];
                self.handle_crypto_passthrough::<McuAesGcmEncryptInitReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_AES_GCM_ENCRYPT_INIT.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_AES_GCM_ENCRYPT_UPDATE => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuAesGcmEncryptUpdateResp>()];
                self.handle_crypto_passthrough::<McuAesGcmEncryptUpdateReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_AES_GCM_ENCRYPT_UPDATE.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_AES_GCM_ENCRYPT_FINAL => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuAesGcmEncryptFinalResp>()];
                self.handle_crypto_passthrough::<McuAesGcmEncryptFinalReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_AES_GCM_ENCRYPT_FINAL.into(),
                    &mut resp_bytes,
                )
                .await
            }
            // Add AES GCM decrypt commands here.
            CommandId::MC_AES_GCM_DECRYPT_INIT => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuAesGcmDecryptInitResp>()];
                self.handle_crypto_passthrough::<McuAesGcmDecryptInitReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_AES_GCM_DECRYPT_INIT.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_AES_GCM_DECRYPT_UPDATE => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuAesGcmDecryptUpdateResp>()];
                self.handle_crypto_passthrough::<McuAesGcmDecryptUpdateReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_AES_GCM_DECRYPT_UPDATE.into(),
                    &mut resp_bytes,
                )
                .await
            }
            CommandId::MC_AES_GCM_DECRYPT_FINAL => {
                let mut resp_bytes = [0u8; core::mem::size_of::<McuAesGcmDecryptFinalResp>()];
                self.handle_crypto_passthrough::<McuAesGcmDecryptFinalReq>(
                    msg_buf,
                    req_len,
                    CaliptraCommandId::CM_AES_GCM_DECRYPT_FINAL.into(),
                    &mut resp_bytes,
                )
                .await
            }
            // TODO: add more command handlers.
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
        // Decode the request
        let req: &FirmwareVersionReq = FirmwareVersionReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        let index = req.index;
        let mut version = FirmwareVersion::default();

        let ret = self
            .non_crypto_cmds_handler
            .get_firmware_version(index, &mut version)
            .await;

        let mbox_cmd_status = if ret.is_ok() && version.len <= MAX_FW_VERSION_STR_LEN {
            MbxCmdStatus::Complete
        } else {
            MbxCmdStatus::Failure
        };

        let mut resp = if mbox_cmd_status == MbxCmdStatus::Complete {
            McuMailboxResp::FirmwareVersion(FirmwareVersionResp {
                hdr: MailboxRespHeaderVarSize {
                    data_len: version.len as u32,
                    ..Default::default()
                },
                version: version.ver_str,
            })
        } else {
            McuMailboxResp::FirmwareVersion(FirmwareVersionResp::default())
        };

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf.
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), mbox_cmd_status))
    }

    async fn handle_device_caps(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        let _req = DeviceCapsReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Prepare response
        let mut caps = DeviceCapabilities::default();
        let ret = self
            .non_crypto_cmds_handler
            .get_device_capabilities(&mut caps)
            .await;

        let mbox_cmd_status = if ret.is_ok() && caps.as_bytes().len() <= DEVICE_CAPS_SIZE {
            MbxCmdStatus::Complete
        } else {
            MbxCmdStatus::Failure
        };

        let mut resp = if mbox_cmd_status == MbxCmdStatus::Complete {
            let mut c = [0u8; DEVICE_CAPS_SIZE];
            c[..caps.as_bytes().len()].copy_from_slice(caps.as_bytes());
            McuMailboxResp::DeviceCaps(DeviceCapsResp {
                hdr: MailboxRespHeader::default(),
                caps: c,
            })
        } else {
            McuMailboxResp::DeviceCaps(DeviceCapsResp::default())
        };

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf.
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), mbox_cmd_status))
    }

    async fn handle_device_id(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        let _req = DeviceIdReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Prepare response
        let mut device_id = DeviceId::default();
        let ret = self
            .non_crypto_cmds_handler
            .get_device_id(&mut device_id)
            .await;

        let mbox_cmd_status = if ret.is_ok() {
            MbxCmdStatus::Complete
        } else {
            MbxCmdStatus::Failure
        };

        let mut resp = McuMailboxResp::DeviceId(DeviceIdResp {
            hdr: MailboxRespHeader::default(),
            vendor_id: device_id.vendor_id,
            device_id: device_id.device_id,
            subsystem_vendor_id: device_id.subsystem_vendor_id,
            subsystem_id: device_id.subsystem_id,
        });

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf.
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), mbox_cmd_status))
    }

    async fn handle_device_info(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        // Decode the request
        let req = DeviceInfoReq::ref_from_bytes(&msg_buf[..req_len])
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Prepare response
        let mut device_info = DeviceInfo::Uid(Default::default());
        let ret = self
            .non_crypto_cmds_handler
            .get_device_info(req.index, &mut device_info)
            .await;

        let mbox_cmd_status = if ret.is_ok() {
            MbxCmdStatus::Complete
        } else {
            MbxCmdStatus::Failure
        };

        let mut resp = if mbox_cmd_status == MbxCmdStatus::Complete {
            let DeviceInfo::Uid(uid) = &device_info;
            let mut data = [0u8; MAX_UID_LEN];
            data[..uid.len].copy_from_slice(&uid.unique_chip_id[..uid.len]);
            McuMailboxResp::DeviceInfo(DeviceInfoResp {
                hdr: MailboxRespHeaderVarSize {
                    data_len: uid.len as u32,
                    ..Default::default()
                },
                data,
            })
        } else {
            McuMailboxResp::DeviceInfo(DeviceInfoResp::default())
        };

        // Populate the checksum for response
        resp.populate_chksum()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        // Encode the response and copy to msg_buf.
        let resp_bytes = resp
            .as_bytes()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        msg_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((resp_bytes.len(), mbox_cmd_status))
    }

    pub async fn handle_crypto_passthrough<T: Default + IntoBytes + FromBytes>(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
        caliptra_cmd_code: u32,
        resp_buf: &mut [u8],
    ) -> Result<(usize, MbxCmdStatus), MsgHandlerError> {
        if req_len > core::mem::size_of::<T>() {
            return Err(MsgHandlerError::InvalidParams);
        }
        let mut req = T::default();
        req.as_mut_bytes()[..req_len].copy_from_slice(&msg_buf[..req_len]);

        // Clear the header checksum field because it was computed for the MCU mailbox CmdID and payload.
        req.as_mut_bytes()[..core::mem::size_of::<MailboxReqHeader>()].fill(0);

        // Invoke Caliptra mailbox API
        let status = execute_mailbox_cmd(
            &self.caliptra_mbox,
            caliptra_cmd_code,
            req.as_mut_bytes(),
            resp_buf,
        )
        .await;

        match status {
            Ok(resp_len) => {
                msg_buf[..resp_len].copy_from_slice(&resp_buf[..resp_len]);
                Ok((resp_len, MbxCmdStatus::Complete))
            }
            Err(_) => Ok((0, MbxCmdStatus::Failure)),
        }
    }
}
