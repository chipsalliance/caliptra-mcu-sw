// Licensed under the Apache-2.0 license

use crate::transport::McuMboxTransport;
use caliptra_api::mailbox::{populate_checksum, CommandId as CaliptraCommandId, MailboxReqHeader};
use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, CommandAuthorizer, DeviceCapabilities, DeviceId, DeviceInfo,
    FirmwareVersion, MAX_UID_LEN,
};
use caliptra_mcu_libapi_caliptra::crypto::rng::Rng;
use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use caliptra_mcu_libsyscall_caliptra::mcu_mbox::MbxCmdStatus;
use caliptra_mcu_libsyscall_caliptra::{caliptra, otp};
use caliptra_mcu_libsyscall_caliptra::{mailbox::Mailbox, DefaultSyscalls};
use caliptra_mcu_mbox_common::messages::{
    CommandId, DeviceCapsReq, DeviceCapsResp, DeviceIdReq, DeviceIdResp, DeviceInfoReq,
    DeviceInfoResp, ExportAttestedCsrReq, ExportAttestedCsrResp, FirmwareVersionReq,
    FirmwareVersionResp, FuseIncreaseCaliptraMinSvnReq, FuseIncreaseCaliptraMinSvnResp,
    FuseRevokeVendorPubKeyReq, FuseRevokeVendorPubKeyResp, FuseWriteResp, GetAuthCmdChallengeReq,
    GetAuthCmdChallengeResp, MailboxRespHeader, MailboxRespHeaderVarSize, McuAesDecryptInitReq,
    McuAesDecryptUpdateReq, McuAesEncryptInitReq, McuAesEncryptUpdateReq, McuAesGcmDecryptFinalReq,
    McuAesGcmDecryptInitReq, McuAesGcmDecryptUpdateReq, McuAesGcmEncryptFinalReq,
    McuAesGcmEncryptInitReq, McuAesGcmEncryptUpdateReq, McuCmDeleteReq, McuCmImportReq,
    McuCmStatusReq, McuEcdhFinishReq, McuEcdhGenerateReq, McuEcdsaCmkPublicKeyReq,
    McuEcdsaCmkSignReq, McuEcdsaCmkVerifyReq, McuFeProgReq, McuFipsSelfTestGetResultsReq,
    McuFipsSelfTestStartReq, McuHkdfExpandReq, McuHkdfExtractReq, McuHmacKdfCounterReq, McuHmacReq,
    McuProdDebugUnlockReqReq, McuProdDebugUnlockTokenReq, McuRandomGenerateReq, McuRandomStirReq,
    McuResponseVarSize, McuShaFinalReq, McuShaInitReq, McuShaUpdateReq, RevokeVendorPubKeyType,
    DEVICE_CAPS_SIZE, MAX_FW_VERSION_STR_LEN, MAX_RESP_DATA_SIZE,
};
#[cfg(feature = "periodic-fips-self-test")]
use caliptra_mcu_mbox_common::messages::{
    McuFipsPeriodicEnableReq, McuFipsPeriodicEnableResp, McuFipsPeriodicStatusReq,
    McuFipsPeriodicStatusResp,
};
use core::sync::atomic::{AtomicBool, Ordering};
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug)]
pub enum MsgHandlerError {
    Transport,
    McuMboxCommon,
    NotReady,
    InvalidParams,
    UnsupportedCommand,
    UnauthorizedCommand,
}

/// Command interface for handling MCU mailbox commands.
pub struct CmdInterface<'a> {
    transport: &'a mut McuMboxTransport,
    non_crypto_cmds_handler: &'a dyn CaliptraCmdHandler,
    cmd_authorizer: &'a mut dyn CommandAuthorizer,
    caliptra_mbox: caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox, // Handle crypto commands via caliptra mailbox
    busy: AtomicBool,
}

impl<'a> CmdInterface<'a> {
    pub fn new(
        transport: &'a mut McuMboxTransport,
        non_crypto_cmds_handler: &'a dyn CaliptraCmdHandler,
        cmd_authorizer: &'a mut dyn CommandAuthorizer,
    ) -> Self {
        Self {
            transport,
            non_crypto_cmds_handler,
            cmd_authorizer,
            caliptra_mbox: Mailbox::new(),
            busy: AtomicBool::new(false),
        }
    }

    /// Handle a MCU mailbox request
    ///
    /// # Arguments
    /// * `req_buf` - Buffer for receiving the command
    /// * `resp_buf` - Buffer for response encoding
    ///
    /// `req_buf` should be sized to fit`size_of::<McuMailboxReq>()` (see [McuMailboxReq](caliptra_mcu_mbox_common::messages::McuMailboxReq)).
    ///
    /// `resp_buf` should be sized to fit `size_of::<McuMailboxResp>()` (see [McuMailboxResp]).
    pub async fn handle_responder_msg(
        &mut self,
        req_buf: &mut [u8],
        resp_buf: &mut [u8],
    ) -> Result<(), MsgHandlerError> {
        // Make sure at least the header can be written to the buffer.
        if resp_buf.len() < size_of::<MailboxRespHeader>() {
            return Err(MsgHandlerError::InvalidParams);
        }

        // Receive a request from the transport.
        let receive_result = self.transport.receive_request(req_buf).await;

        let status = match receive_result {
            Ok((cmd_id, req)) => {
                // Process the request and prepare the response.
                match self.process_request(req, cmd_id, resp_buf).await {
                    Ok((resp, status)) => {
                        if status == MbxCmdStatus::Complete {
                            // guarantee it is big enough to hold the header
                            if resp.len() < size_of::<MailboxRespHeader>() {
                                let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                                return Err(MsgHandlerError::McuMboxCommon);
                            }

                            // Generate response checksum
                            populate_checksum(resp);

                            self.transport.send_response(resp).await.map_err(|_| {
                                let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                                MsgHandlerError::Transport
                            })?;
                        }
                        status
                    }
                    Err(_) => MbxCmdStatus::Failure,
                }
            }
            Err(_) => {
                // If the driver accepted the request but transport-level
                // validation failed, we still need to finalize. If no request
                // was received the finalize is harmlessly rejected.
                let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                return Err(MsgHandlerError::Transport);
            }
        };

        // Finalize the response as the last step of handling the message.
        self.transport
            .finalize_response(status)
            .map_err(|_| MsgHandlerError::Transport)?;

        Ok(())
    }

    async fn process_request<'r>(
        &mut self,
        req: &[u8],
        cmd: u32,
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        if self.busy.load(Ordering::SeqCst) {
            return Err(MsgHandlerError::NotReady);
        }

        self.busy.store(true, Ordering::SeqCst);

        let result = match CommandId::from(cmd) {
            CommandId::MC_FIRMWARE_VERSION => self.handle_fw_version(req, resp_buf).await,
            CommandId::MC_DEVICE_CAPABILITIES => self.handle_device_caps(req, resp_buf).await,
            CommandId::MC_DEVICE_ID => self.handle_device_id(req, resp_buf).await,
            CommandId::MC_DEVICE_INFO => self.handle_device_info(req, resp_buf).await,
            CommandId::MC_FIPS_SELF_TEST_START => {
                self.handle_crypto_passthrough::<McuFipsSelfTestStartReq>(
                    req,
                    CaliptraCommandId::SELF_TEST_START.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_FIPS_SELF_TEST_GET_RESULTS => {
                self.handle_crypto_passthrough::<McuFipsSelfTestGetResultsReq>(
                    req,
                    CaliptraCommandId::SELF_TEST_GET_RESULTS.into(),
                    resp_buf,
                )
                .await
            }
            #[cfg(feature = "periodic-fips-self-test")]
            CommandId::MC_FIPS_PERIODIC_ENABLE => {
                self.handle_fips_periodic_enable(req, resp_buf).await
            }
            #[cfg(feature = "periodic-fips-self-test")]
            CommandId::MC_FIPS_PERIODIC_STATUS => {
                self.handle_fips_periodic_status(req, resp_buf).await
            }
            CommandId::MC_SHA_INIT => {
                self.handle_crypto_passthrough::<McuShaInitReq>(
                    req,
                    CaliptraCommandId::CM_SHA_INIT.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_SHA_UPDATE => {
                self.handle_crypto_passthrough::<McuShaUpdateReq>(
                    req,
                    CaliptraCommandId::CM_SHA_UPDATE.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_SHA_FINAL => {
                self.handle_crypto_passthrough::<McuShaFinalReq>(
                    req,
                    CaliptraCommandId::CM_SHA_FINAL.into(),
                    resp_buf,
                )
                .await
            }
            // Add HMAC command
            CommandId::MC_HMAC => {
                self.handle_crypto_passthrough::<McuHmacReq>(
                    req,
                    CaliptraCommandId::CM_HMAC.into(),
                    resp_buf,
                )
                .await
            }
            // Add HMAC KDF Counter command
            CommandId::MC_HMAC_KDF_COUNTER => {
                self.handle_crypto_passthrough::<McuHmacKdfCounterReq>(
                    req,
                    CaliptraCommandId::CM_HMAC_KDF_COUNTER.into(),
                    resp_buf,
                )
                .await
            }
            // Add HKDF Extract command
            CommandId::MC_HKDF_EXTRACT => {
                self.handle_crypto_passthrough::<McuHkdfExtractReq>(
                    req,
                    CaliptraCommandId::CM_HKDF_EXTRACT.into(),
                    resp_buf,
                )
                .await
            }
            // Add HKDF Expand command
            CommandId::MC_HKDF_EXPAND => {
                self.handle_crypto_passthrough::<McuHkdfExpandReq>(
                    req,
                    CaliptraCommandId::CM_HKDF_EXPAND.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_IMPORT => {
                self.handle_crypto_passthrough::<McuCmImportReq>(
                    req,
                    CaliptraCommandId::CM_IMPORT.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_DELETE => {
                self.handle_crypto_passthrough::<McuCmDeleteReq>(
                    req,
                    CaliptraCommandId::CM_DELETE.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_CM_STATUS => {
                self.handle_crypto_passthrough::<McuCmStatusReq>(
                    req,
                    CaliptraCommandId::CM_STATUS.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_RANDOM_GENERATE => {
                self.handle_crypto_passthrough::<McuRandomGenerateReq>(
                    req,
                    CaliptraCommandId::CM_RANDOM_GENERATE.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_RANDOM_STIR => {
                self.handle_crypto_passthrough::<McuRandomStirReq>(
                    req,
                    CaliptraCommandId::CM_RANDOM_STIR.into(),
                    resp_buf,
                )
                .await
            }
            // Add AES Encrypt commands
            CommandId::MC_AES_ENCRYPT_INIT => {
                self.handle_crypto_passthrough::<McuAesEncryptInitReq>(
                    req,
                    CaliptraCommandId::CM_AES_ENCRYPT_INIT.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_AES_ENCRYPT_UPDATE => {
                self.handle_crypto_passthrough::<McuAesEncryptUpdateReq>(
                    req,
                    CaliptraCommandId::CM_AES_ENCRYPT_UPDATE.into(),
                    resp_buf,
                )
                .await
            }
            // Add AES Decrypt commands
            CommandId::MC_AES_DECRYPT_INIT => {
                self.handle_crypto_passthrough::<McuAesDecryptInitReq>(
                    req,
                    CaliptraCommandId::CM_AES_DECRYPT_INIT.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_AES_DECRYPT_UPDATE => {
                self.handle_crypto_passthrough::<McuAesDecryptUpdateReq>(
                    req,
                    CaliptraCommandId::CM_AES_DECRYPT_UPDATE.into(),
                    resp_buf,
                )
                .await
            }
            // Add AES GCM encrypt commands here.
            CommandId::MC_AES_GCM_ENCRYPT_INIT => {
                self.handle_crypto_passthrough::<McuAesGcmEncryptInitReq>(
                    req,
                    CaliptraCommandId::CM_AES_GCM_ENCRYPT_INIT.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_AES_GCM_ENCRYPT_UPDATE => {
                self.handle_crypto_passthrough::<McuAesGcmEncryptUpdateReq>(
                    req,
                    CaliptraCommandId::CM_AES_GCM_ENCRYPT_UPDATE.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_AES_GCM_ENCRYPT_FINAL => {
                self.handle_crypto_passthrough::<McuAesGcmEncryptFinalReq>(
                    req,
                    CaliptraCommandId::CM_AES_GCM_ENCRYPT_FINAL.into(),
                    resp_buf,
                )
                .await
            }
            // Add AES GCM decrypt commands here.
            CommandId::MC_AES_GCM_DECRYPT_INIT => {
                self.handle_crypto_passthrough::<McuAesGcmDecryptInitReq>(
                    req,
                    CaliptraCommandId::CM_AES_GCM_DECRYPT_INIT.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_AES_GCM_DECRYPT_UPDATE => {
                self.handle_crypto_passthrough::<McuAesGcmDecryptUpdateReq>(
                    req,
                    CaliptraCommandId::CM_AES_GCM_DECRYPT_UPDATE.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_AES_GCM_DECRYPT_FINAL => {
                self.handle_crypto_passthrough::<McuAesGcmDecryptFinalReq>(
                    req,
                    CaliptraCommandId::CM_AES_GCM_DECRYPT_FINAL.into(),
                    resp_buf,
                )
                .await
            }
            // Add ECDH commands
            CommandId::MC_ECDH_GENERATE => {
                self.handle_crypto_passthrough::<McuEcdhGenerateReq>(
                    req,
                    CaliptraCommandId::CM_ECDH_GENERATE.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_ECDH_FINISH => {
                self.handle_crypto_passthrough::<McuEcdhFinishReq>(
                    req,
                    CaliptraCommandId::CM_ECDH_FINISH.into(),
                    resp_buf,
                )
                .await
            }
            // Add ECDSA CMK commands
            CommandId::MC_ECDSA_CMK_PUBLIC_KEY => {
                self.handle_crypto_passthrough::<McuEcdsaCmkPublicKeyReq>(
                    req,
                    CaliptraCommandId::CM_ECDSA_PUBLIC_KEY.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_ECDSA_CMK_SIGN => {
                self.handle_crypto_passthrough::<McuEcdsaCmkSignReq>(
                    req,
                    CaliptraCommandId::CM_ECDSA_SIGN.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_ECDSA_CMK_VERIFY => {
                self.handle_crypto_passthrough::<McuEcdsaCmkVerifyReq>(
                    req,
                    CaliptraCommandId::CM_ECDSA_VERIFY.into(),
                    resp_buf,
                )
                .await
            }
            // Debug Unlock commands
            CommandId::MC_PROD_DEBUG_UNLOCK_REQ => {
                self.handle_crypto_passthrough::<McuProdDebugUnlockReqReq>(
                    req,
                    CaliptraCommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_PROD_DEBUG_UNLOCK_TOKEN => {
                self.handle_crypto_passthrough::<McuProdDebugUnlockTokenReq>(
                    req,
                    CaliptraCommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
                    resp_buf,
                )
                .await
            }
            CommandId::MC_GET_AUTH_CMD_CHALLENGE => {
                self.handle_get_auth_cmd_challenge(req, resp_buf).await
            }
            cmd_id @ CommandId::MC_ROTATE_VENDOR_PK_HASH
            | cmd_id @ CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN
            | cmd_id @ CommandId::MC_FE_PROG
            | cmd_id @ CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY => {
                self.handle_authorized_command(cmd_id, req, resp_buf).await
            }
            // Certificate commands
            CommandId::MC_EXPORT_ATTESTED_CSR => {
                self.handle_export_attested_csr(req, resp_buf).await
            }
            // TODO: add more command handlers.
            // TODO: DOT runtime commands (DOT_CAK_INSTALL, DOT_LOCK, DOT_DISABLE,
            // DOT_UNLOCK_CHALLENGE, DOT_UNLOCK) are not yet handled here. These require
            // Ownership_Storage support and CommandId definitions to be added first.
            _ => Err(MsgHandlerError::UnsupportedCommand),
        };

        self.busy.store(false, Ordering::SeqCst);
        result
    }

    async fn handle_fw_version<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        // Decode the request
        let req: &FirmwareVersionReq =
            FirmwareVersionReq::ref_from_bytes(req).map_err(|_| MsgHandlerError::InvalidParams)?;

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

        let resp = if mbox_cmd_status == MbxCmdStatus::Complete {
            FirmwareVersionResp {
                hdr: MailboxRespHeaderVarSize {
                    data_len: version.len as u32,
                    ..Default::default()
                },
                version: version.ver_str,
            }
        } else {
            FirmwareVersionResp::default()
        };

        // Encode the response and copy to resp_buf.
        let resp_bytes = resp
            .as_bytes_partial()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    async fn handle_device_caps<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        let _req =
            DeviceCapsReq::ref_from_bytes(req).map_err(|_| MsgHandlerError::InvalidParams)?;

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

        let resp = if mbox_cmd_status == MbxCmdStatus::Complete {
            let mut c = [0u8; DEVICE_CAPS_SIZE];
            c[..caps.as_bytes().len()].copy_from_slice(caps.as_bytes());
            DeviceCapsResp {
                hdr: MailboxRespHeader::default(),
                caps: c,
            }
        } else {
            DeviceCapsResp::default()
        };

        // Encode the response and copy to resp_buf.
        let resp_bytes = resp.as_bytes();

        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    async fn handle_device_id<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        let _req = DeviceIdReq::ref_from_bytes(req).map_err(|_| MsgHandlerError::InvalidParams)?;

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

        let resp = DeviceIdResp {
            hdr: MailboxRespHeader::default(),
            vendor_id: device_id.vendor_id,
            device_id: device_id.device_id,
            subsystem_vendor_id: device_id.subsystem_vendor_id,
            subsystem_id: device_id.subsystem_id,
        };

        // Encode the response and copy to resp_buf.
        let resp_bytes = resp.as_bytes();

        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    async fn handle_device_info<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        // Decode the request
        let req = DeviceInfoReq::ref_from_bytes(req).map_err(|_| MsgHandlerError::InvalidParams)?;

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

        let resp = if mbox_cmd_status == MbxCmdStatus::Complete {
            let DeviceInfo::Uid(uid) = &device_info;
            let mut data = [0u8; MAX_UID_LEN];
            data[..uid.len].copy_from_slice(&uid.unique_chip_id[..uid.len]);
            DeviceInfoResp {
                hdr: MailboxRespHeaderVarSize {
                    data_len: uid.len as u32,
                    ..Default::default()
                },
                data,
            }
        } else {
            DeviceInfoResp::default()
        };

        // Encode the response and copy to resp_buf.
        let resp_bytes = resp
            .as_bytes_partial()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    async fn handle_export_attested_csr<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        let req = ExportAttestedCsrReq::ref_from_bytes(req)
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        let mut data = [0u8; MAX_RESP_DATA_SIZE];
        let ret = self
            .non_crypto_cmds_handler
            .export_attested_csr(req.device_key_id, req.algorithm, &req.nonce, &mut data)
            .await;

        let (mbox_cmd_status, data_len) = match ret {
            Ok(len) => (MbxCmdStatus::Complete, len.min(MAX_RESP_DATA_SIZE)),
            Err(_) => (MbxCmdStatus::Failure, 0),
        };

        let resp = if mbox_cmd_status == MbxCmdStatus::Complete {
            ExportAttestedCsrResp {
                hdr: MailboxRespHeaderVarSize {
                    data_len: data_len as u32,
                    ..Default::default()
                },
                data,
            }
        } else {
            ExportAttestedCsrResp::default()
        };

        let resp_bytes = resp
            .as_bytes_partial()
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    async fn handle_get_auth_cmd_challenge<'r>(
        &mut self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        // Decode the request
        let _req = GetAuthCmdChallengeReq::ref_from_bytes(req)
            .map_err(|_| MsgHandlerError::InvalidParams)?;
        let (resp, _) = GetAuthCmdChallengeResp::mut_from_prefix(resp_buf)
            .map_err(|_| MsgHandlerError::InvalidParams)?;
        *resp = GetAuthCmdChallengeResp::default();

        Rng::generate_random_number(&mut resp.challenge)
            .await
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        self.cmd_authorizer.set_challenge(resp.challenge);
        let len = size_of_val(resp);
        Ok((&mut resp_buf[..len], MbxCmdStatus::Complete))
    }

    pub async fn handle_crypto_passthrough<'r, T: Default + IntoBytes + FromBytes>(
        &self,
        req: &[u8],
        caliptra_cmd_code: u32,
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        let mut caliptra_req = T::default();
        caliptra_req
            .as_mut_bytes()
            .get_mut(..req.len())
            .ok_or(MsgHandlerError::InvalidParams)?
            .copy_from_slice(req);

        // Clear the header checksum field because it was computed for the MCU mailbox CmdID and payload.
        caliptra_req.as_mut_bytes()[..core::mem::size_of::<MailboxReqHeader>()].fill(0);

        // Invoke Caliptra mailbox API
        let status = execute_mailbox_cmd(
            &self.caliptra_mbox,
            caliptra_cmd_code,
            caliptra_req.as_mut_bytes(),
            resp_buf,
        )
        .await;

        match status {
            Ok(resp_len) => Ok((&mut resp_buf[..resp_len], MbxCmdStatus::Complete)),
            Err(_) => Ok((&mut resp_buf[..0], MbxCmdStatus::Failure)),
        }
    }

    async fn handle_authorized_command<'r>(
        &mut self,
        cmd_id: CommandId,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        let cmd = self
            .cmd_authorizer
            .is_authorized(cmd_id, req)
            .await
            .map_err(|_| MsgHandlerError::UnauthorizedCommand)?;
        match cmd_id {
            CommandId::MC_ROTATE_VENDOR_PK_HASH => {
                self.handle_rotate_vendor_pk_hash(cmd, resp_buf).await
            }
            CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN => {
                self.handle_increase_caliptra_min_svn(cmd, resp_buf).await
            }
            CommandId::MC_FE_PROG => self.handle_fe_prog(cmd, resp_buf).await,
            CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY => {
                self.handle_revoke_vendor_pub_key(cmd, resp_buf).await
            }
            _ => Err(MsgHandlerError::UnsupportedCommand),
        }
    }

    async fn handle_rotate_vendor_pk_hash<'r>(
        &self,
        _req: &[u8],
        _resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        // TODO
        Err(MsgHandlerError::UnsupportedCommand)
    }

    async fn handle_increase_caliptra_min_svn<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        if resp_buf.len() < core::mem::size_of::<FuseIncreaseCaliptraMinSvnResp>() {
            return Err(MsgHandlerError::InvalidParams);
        }

        // Decode the request
        let req = FuseIncreaseCaliptraMinSvnReq::ref_from_bytes(req)
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Check the request has a valid SVN value
        if req.svn == 0 {
            return Err(MsgHandlerError::InvalidParams);
        }
        if req.svn > 128 {
            return Err(MsgHandlerError::InvalidParams);
        }

        let caliptra_fw_info = self.get_caliptra_fw_info().await?;

        // Ensure the requested SVN will allow current Caliptra firmware to run
        if req.svn > caliptra_fw_info.fw_svn {
            return Err(MsgHandlerError::InvalidParams);
        }

        // Get the minimum SVN set in fuses
        let otp: otp::Otp<DefaultSyscalls> = otp::Otp::new();
        let mut current_fuses = [0u32; 4];
        for (i, fuse) in current_fuses.iter_mut().enumerate() {
            *fuse = otp
                .read(otp::reg::CALIPTRA_FW_SVN, i as u32)
                .map_err(|_| MsgHandlerError::McuMboxCommon)?;
        }

        // Convert the fuses to the SVN value
        let fused_min_svn = {
            // Value is take as the most significant bit set in fuses
            let fuse: u128 = u128::from_le_bytes(current_fuses.as_bytes().try_into().unwrap());
            128 - fuse.leading_zeros()
        };

        // Ensure we are not trying to decrease the SVN
        if req.svn < fused_min_svn {
            return Err(MsgHandlerError::InvalidParams);
        }

        // We are done, if the fuses already match the requested SVN.
        if fused_min_svn == req.svn {
            let resp = FuseIncreaseCaliptraMinSvnResp::default();
            let resp_bytes = resp.as_bytes();
            resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);
            return Ok((&mut resp_buf[..resp_bytes.len()], MbxCmdStatus::Complete));
        }

        let new_fuse_svn = if req.svn == 128 {
            u128::MAX
        } else {
            !(u128::MAX << req.svn)
        };

        for (i, (current, new_bytes)) in current_fuses
            .iter()
            .zip(new_fuse_svn.as_bytes().chunks_exact(4))
            .enumerate()
        {
            let new_svn_word = u32::from_le_bytes(new_bytes.try_into().unwrap());
            if *current != new_svn_word {
                otp.write(otp::reg::CALIPTRA_FW_SVN, i as u32, new_svn_word)
                    .map_err(|_| MsgHandlerError::InvalidParams)?;
            }
        }

        let resp = FuseIncreaseCaliptraMinSvnResp::default();
        let resp_bytes = resp.as_bytes();
        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok((&mut resp_buf[..resp_bytes.len()], MbxCmdStatus::Complete))
    }

    async fn handle_fe_prog<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        // Decode the request
        let req = McuFeProgReq::ref_from_bytes(req).map_err(|_| MsgHandlerError::InvalidParams)?;
        let (resp, _) =
            FuseWriteResp::mut_from_prefix(resp_buf).map_err(|_| MsgHandlerError::InvalidParams)?;

        // Prepare Caliptra request
        let mut caliptra_req = caliptra_api::mailbox::FeProgReq {
            partition: req.partition,
            ..Default::default()
        };

        // Calculate checksum
        caliptra_req.hdr.chksum =
            caliptra_api::calc_checksum(CaliptraCommandId::FE_PROG.into(), caliptra_req.as_bytes());

        // Invoke Caliptra mailbox API
        let _caliptra_resp_len = execute_mailbox_cmd(
            &self.caliptra_mbox,
            CaliptraCommandId::FE_PROG.into(),
            caliptra_req.as_mut_bytes(),
            resp.as_mut_bytes(),
        )
        .await
        .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        *resp = FuseWriteResp::default();
        let resp_len = resp.as_bytes().len();
        Ok((&mut resp_buf[..resp_len], MbxCmdStatus::Complete))
    }

    async fn handle_revoke_vendor_pub_key<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        let req = FuseRevokeVendorPubKeyReq::ref_from_bytes(req)
            .map_err(|_| MsgHandlerError::InvalidParams)?;
        let (resp, _) = FuseRevokeVendorPubKeyResp::mut_from_prefix(resp_buf)
            .map_err(|_| MsgHandlerError::InvalidParams)?;
        let key_type = RevokeVendorPubKeyType::try_from(req.key_type)
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Check the given slot has a valid PK hash provisioned
        let otp = otp::Otp::<DefaultSyscalls>::new();
        if !otp.valid_vendor_pk_hash_slot(req.vendor_pk_hash_slot) {
            Err(MsgHandlerError::InvalidParams)?;
        }

        let caliptra_info = self.get_caliptra_fw_info().await?;

        // Check if the key to be revoked was a key used to boot. If so, return an error as a form
        // of proof of possession for other keys.
        let same_key_used_to_boot = || {
            let caliptra_soc = caliptra::Caliptra::<DefaultSyscalls>::new();
            let booted_pk_hash = caliptra_soc
                .read_vendor_pk_hash()
                .map_err(|_| MsgHandlerError::McuMboxCommon)?;
            let pk_hash_from_slot = otp
                .read_vendor_pk_hash(req.vendor_pk_hash_slot)
                .map_err(|_| MsgHandlerError::McuMboxCommon)?;

            // Check if the requested slot was the one used to boot
            if booted_pk_hash != pk_hash_from_slot {
                return Ok(false);
            }

            const FW_VERIFICATION_PQC_TYPE_MLDSA: u32 = 1;
            const FW_VERIFICATION_PQC_TYPE_LMS: u32 = 3;
            let same_key = match (key_type, caliptra_info.image_manifest_pqc_type) {
                (RevokeVendorPubKeyType::Ecdsa384, _) => {
                    req.key_index == caliptra_info.vendor_ecc384_pub_key_index
                }
                // Same PQC type
                (RevokeVendorPubKeyType::Lms, FW_VERIFICATION_PQC_TYPE_LMS)
                | (RevokeVendorPubKeyType::Mldsa87, FW_VERIFICATION_PQC_TYPE_MLDSA) => {
                    req.key_index == caliptra_info.vendor_pqc_pub_key_index
                }
                // Different PQC types
                _ => false,
            };
            Ok(same_key)
        };

        if same_key_used_to_boot()? {
            Err(MsgHandlerError::InvalidParams)?;
        }

        otp.revoke_vendor_pub_key(req.vendor_pk_hash_slot, key_type, req.key_index)
            .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        *resp = FuseRevokeVendorPubKeyResp::default();
        let len = size_of_val(resp);
        Ok((&mut resp_buf[..len], MbxCmdStatus::Complete))
    }

    async fn get_caliptra_fw_info(
        &self,
    ) -> Result<caliptra_api::mailbox::FwInfoResp, MsgHandlerError> {
        let mut req = caliptra_api::mailbox::MailboxReqHeader::default();
        let mut caliptra_info = caliptra_api::mailbox::FwInfoResp {
            hdr: Default::default(),
            pl0_pauser: Default::default(),
            fw_svn: Default::default(),
            min_fw_svn: Default::default(),
            cold_boot_fw_svn: Default::default(),
            attestation_disabled: Default::default(),
            rom_revision: Default::default(),
            fmc_revision: Default::default(),
            runtime_revision: Default::default(),
            rom_sha256_digest: Default::default(),
            fmc_sha384_digest: Default::default(),
            runtime_sha384_digest: Default::default(),
            owner_pub_key_hash: Default::default(),
            authman_sha384_digest: Default::default(),
            most_recent_fw_error: Default::default(),
            vendor_pub_key_hash: Default::default(),
            image_manifest_pqc_type: Default::default(),
            vendor_ecc384_pub_key_index: Default::default(),
            vendor_pqc_pub_key_index: Default::default(),
        };

        // Invoke Caliptra mailbox API
        let len = execute_mailbox_cmd(
            &self.caliptra_mbox,
            caliptra_api::mailbox::CommandId::FW_INFO.into(),
            req.as_mut_bytes(),
            caliptra_info.as_mut_bytes(),
        )
        .await
        .map_err(|_| MsgHandlerError::McuMboxCommon)?;

        if len < size_of_val(&caliptra_info) {
            return Err(MsgHandlerError::McuMboxCommon);
        }
        Ok(caliptra_info)
    }

    #[cfg(feature = "periodic-fips-self-test")]
    async fn handle_fips_periodic_enable<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        use crate::fips_periodic;

        // Parse the request
        let req = McuFipsPeriodicEnableReq::ref_from_bytes(req)
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Enable or disable based on request
        fips_periodic::set_enabled(req.enable != 0);

        // Prepare response
        let resp = McuFipsPeriodicEnableResp(MailboxRespHeader::default());

        // Encode the response and copy to resp_buf
        let resp_bytes = resp.as_bytes();
        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((&mut resp_buf[..resp_bytes.len()], MbxCmdStatus::Complete))
    }

    #[cfg(feature = "periodic-fips-self-test")]
    async fn handle_fips_periodic_status<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> Result<(&'r mut [u8], MbxCmdStatus), MsgHandlerError> {
        use crate::fips_periodic;

        // Parse the request (just header, no additional data)
        let _req = McuFipsPeriodicStatusReq::ref_from_bytes(req)
            .map_err(|_| MsgHandlerError::InvalidParams)?;

        // Get status
        let (enabled, iterations, last_result) = fips_periodic::get_status();

        // Prepare response
        let resp = McuFipsPeriodicStatusResp {
            header: MailboxRespHeader::default(),
            enabled: if enabled { 1 } else { 0 },
            iterations,
            last_result,
        };

        // Encode the response and copy to resp_buf
        let resp_bytes = resp.as_bytes();

        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((&mut resp_buf[..resp_bytes.len()], MbxCmdStatus::Complete))
    }
}
