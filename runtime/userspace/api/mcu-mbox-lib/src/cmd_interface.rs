// Licensed under the Apache-2.0 license

use crate::errors;
use crate::transport::McuMboxTransport;
use caliptra_api::mailbox::{populate_checksum, CommandId as CaliptraCommandId, MailboxReqHeader};
use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, CommandAuthorizer, DeviceCapabilities, DeviceId, DeviceInfo,
    FirmwareVersion, GetLogResult, MAX_UID_LEN,
};
use caliptra_mcu_libapi_caliptra::crypto::rng::Rng;
use caliptra_mcu_libapi_caliptra::mailbox_api::execute_mailbox_cmd;
use caliptra_mcu_libsyscall_caliptra::mcu_mbox::MbxCmdStatus;
use caliptra_mcu_libsyscall_caliptra::otp::Otp;
use caliptra_mcu_libsyscall_caliptra::{caliptra, otp};
use caliptra_mcu_libsyscall_caliptra::{mailbox::Mailbox, DefaultSyscalls};
use caliptra_mcu_mbox_common::messages::{
    ClearLogReq, ClearLogResp, CommandId, DeviceCapsReq, DeviceCapsResp, DeviceIdReq, DeviceIdResp,
    DeviceInfoReq, DeviceInfoResp, ExportAttestedCsrReq, ExportAttestedCsrResp, FirmwareVersionReq,
    FirmwareVersionResp, FuseIncreaseCaliptraMinSvnReq, FuseIncreaseCaliptraMinSvnResp,
    FuseLockPartitionReq, FuseLockPartitionResp, FuseReadReq, FuseReadResp,
    FuseRevokeVendorPkHashReq, FuseRevokeVendorPkHashResp, FuseRevokeVendorPubKeyReq,
    FuseRevokeVendorPubKeyResp, FuseWriteReq, FuseWriteResp, GetAuthCmdChallengeReq,
    GetAuthCmdChallengeResp, GetLogReq, GetLogResp, MailboxRespHeader, MailboxRespHeaderVarSize,
    McuFeProgReq, McuResponseVarSize, OcpLockRotateHekReq, OcpLockRotateHekResp,
    OcpLockSetPermaHekReq, OcpLockSetPermaHekResp, ProvisionVendorPkHashReq,
    ProvisionVendorPkHashResp, RevokeVendorPubKeyType, DEVICE_CAPS_SIZE, MAX_FUSE_DATA_SIZE,
    MAX_FW_VERSION_STR_LEN, MAX_RESP_DATA_SIZE,
};
#[cfg(feature = "periodic-fips-self-test")]
use caliptra_mcu_mbox_common::messages::{
    McuFipsPeriodicEnableReq, McuFipsPeriodicEnableResp, McuFipsPeriodicStatusReq,
    McuFipsPeriodicStatusResp,
};

use caliptra_mcu_romtime::{fuse_read_dai_params, PartitionId};

use core::sync::atomic::{AtomicBool, Ordering};
use mcu_error::McuResult;
use zerocopy::{FromBytes, IntoBytes};

/// Command interface for handling MCU mailbox commands.
pub struct CmdInterface<'a> {
    transport: &'a mut McuMboxTransport,
    non_crypto_cmds_handler: &'a dyn CaliptraCmdHandler,
    cmd_authorizer: &'a mut dyn CommandAuthorizer,
    caliptra_mbox: caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox, // Handle crypto commands via caliptra mailbox
    otp: caliptra_mcu_libsyscall_caliptra::otp::Otp,
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
            otp: Otp::new(),
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
    ) -> McuResult<()> {
        // Make sure at least the header can be written to the buffer.
        if resp_buf.len() < size_of::<MailboxRespHeader>() {
            return Err(errors::INVALID_PARAMS);
        }

        // Receive a request from the transport.
        let (cmd_id, req_len) = match self.transport.receive_request(req_buf).await {
            Ok((c, slice)) => (c, slice.len()),
            Err(_) => {
                let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                return Err(errors::TRANSPORT_ERROR);
            }
        };

        let status = match self
            .process_request(req_buf, req_len, cmd_id, resp_buf)
            .await
        {
            Ok((resp, status)) => {
                if status == MbxCmdStatus::Complete {
                    // guarantee it is big enough to hold the header
                    if resp.len() < size_of::<MailboxRespHeader>() {
                        let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                        return Err(errors::MCU_MBOX_COMMON);
                    }

                    // Generate response checksum
                    populate_checksum(resp);

                    self.transport.send_response(resp).await.map_err(|_| {
                        let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                        errors::TRANSPORT_ERROR
                    })?;
                }
                status
            }
            Err(_) => MbxCmdStatus::Failure,
        };

        // Finalize the response as the last step of handling the message.
        self.transport
            .finalize_response(status)
            .map_err(|_| errors::TRANSPORT_ERROR)?;

        Ok(())
    }

    async fn process_request<'r>(
        &mut self,
        req_buf: &mut [u8],
        req_len: usize,
        cmd: u32,
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        if self.busy.load(Ordering::SeqCst) {
            return Err(errors::NOT_READY);
        }

        self.busy.store(true, Ordering::SeqCst);

        let cmd_id = CommandId::from(cmd);
        let result = if let Some(caliptra_cmd) = caliptra_passthrough_cmd(cmd_id) {
            self.handle_crypto_passthrough(req_buf, req_len, caliptra_cmd, resp_buf)
                .await
        } else {
            let req = req_buf.get(..req_len).ok_or(errors::INVALID_PARAMS)?;
            match cmd_id {
                CommandId::MC_FIRMWARE_VERSION => self.handle_fw_version(req, resp_buf).await,
                CommandId::MC_DEVICE_CAPABILITIES => self.handle_device_caps(req, resp_buf).await,
                CommandId::MC_DEVICE_ID => self.handle_device_id(req, resp_buf).await,
                CommandId::MC_DEVICE_INFO => self.handle_device_info(req, resp_buf).await,
                CommandId::MC_GET_LOG => self.handle_get_log(req, resp_buf).await,
                CommandId::MC_CLEAR_LOG => self.handle_clear_log(req, resp_buf).await,
                #[cfg(feature = "periodic-fips-self-test")]
                CommandId::MC_FIPS_PERIODIC_ENABLE => {
                    self.handle_fips_periodic_enable(req, resp_buf).await
                }
                #[cfg(feature = "periodic-fips-self-test")]
                CommandId::MC_FIPS_PERIODIC_STATUS => {
                    self.handle_fips_periodic_status(req, resp_buf).await
                }
                CommandId::MC_GET_AUTH_CMD_CHALLENGE => {
                    self.handle_get_auth_cmd_challenge(req, resp_buf).await
                }
                inner @ CommandId::MC_PROVISION_VENDOR_PK_HASH
                | inner @ CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN
                | inner @ CommandId::MC_FE_PROG
                | inner @ CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH
                | inner @ CommandId::MC_FUSE_READ
                | inner @ CommandId::MC_FUSE_WRITE
                | inner @ CommandId::MC_FUSE_LOCK_PARTITION
                | inner @ CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY
                | inner @ CommandId::MC_OCP_LOCK_ROTATE_HEK
                | inner @ CommandId::MC_OCP_LOCK_SET_PERMA_HEK => {
                    self.handle_authorized_command(inner, req, resp_buf).await
                }
                CommandId::MC_EXPORT_ATTESTED_CSR => {
                    self.handle_export_attested_csr(req, resp_buf).await
                }

                _ => Err(errors::UNSUPPORTED_COMMAND),
            }
        };

        self.busy.store(false, Ordering::SeqCst);
        result
    }

    async fn handle_fw_version<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        // Decode the request
        let req: &FirmwareVersionReq =
            FirmwareVersionReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

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
            .map_err(|_| errors::MCU_MBOX_COMMON)?;

        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    async fn handle_device_caps<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let _req = DeviceCapsReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

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
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let _req = DeviceIdReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

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
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        // Decode the request
        let req = DeviceInfoReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

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
            .map_err(|_| errors::MCU_MBOX_COMMON)?;

        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    /// Handle `MC_GET_LOG` (0x4D47_4C47).
    ///
    /// Wire format of the response payload (after `MailboxRespHeaderVarSize`):
    ///   `[u32 more_data][u8; n log entries]`
    ///
    /// `more_data` is `1` if at least one further log entry remains that did
    /// not fit in the response buffer, `0` otherwise. `data_len` in the header
    /// covers both the `more_data` field and the log bytes (i.e.
    /// `4 + n` bytes).
    async fn handle_get_log<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req = GetLogReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

        // Reserve the first 4 bytes of the variable-length payload for the
        // `more_data` flag; the rest is filled by the handler.
        const MORE_DATA_FIELD_LEN: usize = core::mem::size_of::<u32>();
        let mut resp = GetLogResp::default();
        let result = self
            .non_crypto_cmds_handler
            .get_log(req.log_type, &mut resp.data[MORE_DATA_FIELD_LEN..])
            .await;

        let mbox_cmd_status = match result {
            Ok(GetLogResult {
                bytes_written,
                more_data,
            }) => {
                let more_data_bytes: u32 = if more_data { 1 } else { 0 };
                resp.data[..MORE_DATA_FIELD_LEN].copy_from_slice(&more_data_bytes.to_le_bytes());
                resp.hdr = MailboxRespHeaderVarSize {
                    data_len: (MORE_DATA_FIELD_LEN + bytes_written) as u32,
                    ..Default::default()
                };
                MbxCmdStatus::Complete
            }
            Err(_) => {
                resp = GetLogResp::default();
                MbxCmdStatus::Failure
            }
        };

        let resp_bytes = resp
            .as_bytes_partial()
            .map_err(|_| errors::MCU_MBOX_COMMON)?;
        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    /// Handle `MC_CLEAR_LOG` (0x4D43_4C47).
    async fn handle_clear_log<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req = ClearLogReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

        let mbox_cmd_status = match self.non_crypto_cmds_handler.clear_log(req.log_type).await {
            Ok(()) => MbxCmdStatus::Complete,
            Err(_) => MbxCmdStatus::Failure,
        };

        let resp = ClearLogResp::default();
        let resp_bytes = resp.as_bytes();
        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    async fn handle_export_attested_csr<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req = ExportAttestedCsrReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

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
            .map_err(|_| errors::MCU_MBOX_COMMON)?;

        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);

        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    async fn handle_get_auth_cmd_challenge<'r>(
        &mut self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        // Decode the request
        let _req =
            GetAuthCmdChallengeReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        let (resp, _) = GetAuthCmdChallengeResp::mut_from_prefix(resp_buf)
            .map_err(|_| errors::INVALID_PARAMS)?;
        *resp = GetAuthCmdChallengeResp::default();

        Rng::generate_random_number(&mut resp.challenge)
            .await
            .map_err(|_| errors::MCU_MBOX_COMMON)?;

        self.cmd_authorizer.set_challenge(resp.challenge);
        let len = size_of_val(resp);
        Ok((&mut resp_buf[..len], MbxCmdStatus::Complete))
    }

    pub async fn handle_crypto_passthrough<'r>(
        &mut self,
        req_buf: &mut [u8],
        req_len: usize,
        caliptra_cmd_code: u32,
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req = req_buf.get_mut(..req_len).ok_or(errors::INVALID_PARAMS)?;

        // Clear the header checksum field because it was computed for the MCU mailbox CmdID and payload.
        req[..core::mem::size_of::<MailboxReqHeader>()].fill(0);

        let status =
            execute_mailbox_cmd(&self.caliptra_mbox, caliptra_cmd_code, req, resp_buf).await;

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
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let cmd = self
            .cmd_authorizer
            .is_authorized(cmd_id, req)
            .await
            .map_err(|_| errors::UNAUTHORIZED_COMMAND)?;
        match cmd_id {
            CommandId::MC_PROVISION_VENDOR_PK_HASH => {
                self.handle_provision_vendor_pk_hash(cmd, resp_buf).await
            }
            CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN => {
                self.handle_increase_caliptra_min_svn(cmd, resp_buf).await
            }
            CommandId::MC_FE_PROG => self.handle_fe_prog(cmd, resp_buf).await,
            CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY => {
                self.handle_revoke_vendor_pub_key(cmd, resp_buf).await
            }
            CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH => {
                self.handle_revoke_vendor_pk_hash(cmd, resp_buf).await
            }
            CommandId::MC_FUSE_READ => self.handle_fuse_read(cmd, resp_buf).await,
            CommandId::MC_FUSE_WRITE => self.handle_fuse_write(cmd, resp_buf).await,
            CommandId::MC_FUSE_LOCK_PARTITION => {
                self.handle_fuse_lock_partition(cmd, resp_buf).await
            }
            CommandId::MC_OCP_LOCK_ROTATE_HEK => {
                self.handle_ocp_lock_rotate_hek(cmd, resp_buf).await
            }
            CommandId::MC_OCP_LOCK_SET_PERMA_HEK => {
                self.handle_ocp_lock_set_perma_hek(cmd, resp_buf).await
            }
            _ => Err(errors::UNSUPPORTED_COMMAND),
        }
    }

    async fn handle_fuse_read<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        // Decode the request
        let req = FuseReadReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        let (resp, _) =
            FuseReadResp::mut_from_prefix(resp_buf).map_err(|_| errors::INVALID_PARAMS)?;

        *resp = FuseReadResp::default();

        let params = fuse_read_dai_params(req.partition, req.entry, MAX_FUSE_DATA_SIZE / 4)
            .map_err(|_| errors::INVALID_PARAMS)?;

        let otp: otp::Otp<DefaultSyscalls> = otp::Otp::new();

        // Create a iterator over the words in the response that yields at most `params.words_to_read`
        // (which is less or equal to the words in resp.data).
        let words = resp.data.chunks_exact_mut(4).take(params.words_to_read);
        for (i, word) in words.enumerate() {
            let data = otp
                .read_raw(params.base_word_addr as u32, i as u32)
                .map_err(|_| errors::MCU_MBOX_COMMON)?;
            let bytes = data.to_ne_bytes();
            word.copy_from_slice(&bytes);
        }

        resp.length_bits = params.valid_bits;

        Ok((resp.as_mut_bytes(), MbxCmdStatus::Complete))
    }

    async fn handle_fuse_write<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        // Decode the request
        let req = FuseWriteReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        let (resp, _) =
            FuseWriteResp::mut_from_prefix(resp_buf).map_err(|_| errors::INVALID_PARAMS)?;

        let otp: otp::Otp<DefaultSyscalls> = otp::Otp::new();

        otp.write_raw(req.word_addr, req.data, req.mask)
            .map_err(|e| match e {
                caliptra_mcu_libtock_platform::ErrorCode::Fail => errors::MCU_MBOX_COMMON,
                caliptra_mcu_libtock_platform::ErrorCode::Invalid => errors::INVALID_PARAMS,
                _ => errors::MCU_MBOX_COMMON,
            })?;

        *resp = FuseWriteResp::default();

        Ok((resp.as_mut_bytes(), MbxCmdStatus::Complete))
    }

    async fn handle_fuse_lock_partition<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        // Decode the request
        let req = FuseLockPartitionReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        let (resp, _) =
            FuseLockPartitionResp::mut_from_prefix(resp_buf).map_err(|_| errors::INVALID_PARAMS)?;

        PartitionId::try_from(req.partition).map_err(|_| errors::INVALID_PARAMS)?;

        let otp: otp::Otp<DefaultSyscalls> = otp::Otp::new();
        otp.lock_partition(req.partition)
            .map_err(|_| errors::MCU_MBOX_COMMON)?;

        *resp = FuseLockPartitionResp::default();
        Ok((resp.as_mut_bytes(), MbxCmdStatus::Complete))
    }

    async fn handle_provision_vendor_pk_hash<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req =
            ProvisionVendorPkHashReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        let otp: Otp<DefaultSyscalls> = Otp::new();
        let res = match otp.provision_vendor_pk_hash(req.slot, &req.hash) {
            Ok(_) => MbxCmdStatus::Complete,
            Err(_) => MbxCmdStatus::Failure,
        };
        let resp = ProvisionVendorPkHashResp::default();
        let resp_slice = &mut resp_buf[..size_of::<ProvisionVendorPkHashResp>()];
        resp.write_to(resp_slice).unwrap();
        Ok((resp_slice, res))
    }

    async fn handle_increase_caliptra_min_svn<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        if resp_buf.len() < core::mem::size_of::<FuseIncreaseCaliptraMinSvnResp>() {
            return Err(errors::INVALID_PARAMS);
        }

        // Decode the request
        let req = FuseIncreaseCaliptraMinSvnReq::ref_from_bytes(req)
            .map_err(|_| errors::INVALID_PARAMS)?;

        // Check the request has a valid SVN value
        if req.svn == 0 {
            return Err(errors::INVALID_PARAMS);
        }
        if req.svn > 128 {
            return Err(errors::INVALID_PARAMS);
        }

        let caliptra_fw_info = self.get_caliptra_fw_info().await?;

        // Ensure the requested SVN will allow current Caliptra firmware to run
        if req.svn > caliptra_fw_info.fw_svn {
            return Err(errors::INVALID_PARAMS);
        }

        // Get the minimum SVN set in fuses
        let otp: otp::Otp<DefaultSyscalls> = otp::Otp::new();
        let mut current_fuses = [0u32; 4];
        for (i, fuse) in current_fuses.iter_mut().enumerate() {
            *fuse = otp
                .read(otp::reg::CALIPTRA_FW_SVN, i as u32)
                .map_err(|_| errors::MCU_MBOX_COMMON)?;
        }

        // Convert the fuses to the SVN value
        let fused_min_svn = {
            // Value is take as the most significant bit set in fuses
            let fuse: u128 = u128::from_le_bytes(current_fuses.as_bytes().try_into().unwrap());
            128 - fuse.leading_zeros()
        };

        // Ensure we are not trying to decrease the SVN
        if req.svn < fused_min_svn {
            return Err(errors::INVALID_PARAMS);
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
                    .map_err(|_| errors::INVALID_PARAMS)?;
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
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        // Decode the request
        let req = McuFeProgReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        let (resp, _) =
            FuseWriteResp::mut_from_prefix(resp_buf).map_err(|_| errors::INVALID_PARAMS)?;

        // Prepare Caliptra request
        let mut caliptra_req = caliptra_api::mailbox::FeProgReq {
            partition: req.partition,
            ..Default::default()
        };

        // Invoke Caliptra mailbox API (checksum is computed by execute_mailbox_cmd)
        let _caliptra_resp_len = execute_mailbox_cmd(
            &self.caliptra_mbox,
            CaliptraCommandId::FE_PROG.into(),
            caliptra_req.as_mut_bytes(),
            resp.as_mut_bytes(),
        )
        .await
        .map_err(|_| errors::MCU_MBOX_COMMON)?;

        *resp = FuseWriteResp::default();
        let resp_len = resp.as_bytes().len();
        Ok((&mut resp_buf[..resp_len], MbxCmdStatus::Complete))
    }

    async fn handle_revoke_vendor_pub_key<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req =
            FuseRevokeVendorPubKeyReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        let (resp, _) = FuseRevokeVendorPubKeyResp::mut_from_prefix(resp_buf)
            .map_err(|_| errors::INVALID_PARAMS)?;
        let key_type =
            RevokeVendorPubKeyType::try_from(req.key_type).map_err(|_| errors::INVALID_PARAMS)?;

        // Check the given slot has a valid PK hash provisioned
        let otp = otp::Otp::<DefaultSyscalls>::new();
        if !otp.valid_vendor_pk_hash_slot(req.vendor_pk_hash_slot) {
            Err(errors::INVALID_PARAMS)?;
        }

        let caliptra_info = self.get_caliptra_fw_info().await?;

        // Check if the key to be revoked was a key used to boot. If so, return an error as a form
        // of proof of possession for other keys.
        let same_key_used_to_boot = || -> McuResult<bool> {
            let caliptra_soc = caliptra::Caliptra::<DefaultSyscalls>::new();
            let booted_pk_hash = caliptra_soc
                .read_vendor_pk_hash()
                .map_err(|_| errors::MCU_MBOX_COMMON)?;
            let pk_hash_from_slot = otp
                .read_vendor_pk_hash(req.vendor_pk_hash_slot)
                .map_err(|_| errors::MCU_MBOX_COMMON)?;

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
            Err(errors::INVALID_PARAMS)?;
        }

        otp.revoke_vendor_pub_key(req.vendor_pk_hash_slot, key_type, req.key_index)
            .map_err(|_| errors::MCU_MBOX_COMMON)?;

        *resp = FuseRevokeVendorPubKeyResp::default();
        let len = size_of_val(resp);
        Ok((&mut resp_buf[..len], MbxCmdStatus::Complete))
    }

    async fn handle_revoke_vendor_pk_hash<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        // Decode the request
        let req =
            FuseRevokeVendorPkHashReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        let (resp, _) = FuseRevokeVendorPkHashResp::mut_from_prefix(resp_buf)
            .map_err(|_| errors::INVALID_PARAMS)?;

        let otp = otp::Otp::<DefaultSyscalls>::new();

        // Check if the PK hash to be revoked was used to boot. If so, return an error as a form
        // of proof of possession for other keys.
        let same_key_used_to_boot = || -> McuResult<bool> {
            let caliptra_soc = caliptra::Caliptra::<DefaultSyscalls>::new();
            let booted_pk_hash = caliptra_soc
                .read_vendor_pk_hash()
                .map_err(|_| errors::MCU_MBOX_COMMON)?;
            let pk_hash_from_slot = otp
                .read_vendor_pk_hash(req.vendor_pk_hash_slot)
                .map_err(|_| errors::MCU_MBOX_COMMON)?;

            // Check if the requested slot was the one used to boot
            Ok(booted_pk_hash == pk_hash_from_slot)
        };

        if same_key_used_to_boot()? {
            Err(errors::INVALID_PARAMS)?;
        }

        otp.revoke_vendor_pk_hash(req.vendor_pk_hash_slot)
            .map_err(|_| errors::MCU_MBOX_COMMON)?;

        *resp = FuseRevokeVendorPkHashResp::default();
        let resp_len = resp.as_bytes().len();
        Ok((&mut resp_buf[..resp_len], MbxCmdStatus::Complete))
    }

    async fn get_caliptra_fw_info(&self) -> McuResult<caliptra_api::mailbox::FwInfoResp> {
        let mut req = caliptra_api::mailbox::MailboxReqHeader::default();
        use zerocopy::FromZeros;
        let mut caliptra_info = caliptra_api::mailbox::FwInfoResp::new_zeroed();

        // Invoke Caliptra mailbox API
        let len = execute_mailbox_cmd(
            &self.caliptra_mbox,
            caliptra_api::mailbox::CommandId::FW_INFO.into(),
            req.as_mut_bytes(),
            caliptra_info.as_mut_bytes(),
        )
        .await
        .map_err(|_| errors::MCU_MBOX_COMMON)?;

        if len < size_of_val(&caliptra_info) {
            return Err(errors::MCU_MBOX_COMMON);
        }
        Ok(caliptra_info)
    }

    #[cfg(feature = "periodic-fips-self-test")]
    async fn handle_fips_periodic_enable<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        use crate::fips_periodic;

        // Parse the request
        let req =
            McuFipsPeriodicEnableReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

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
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        use crate::fips_periodic;

        // Parse the request (just header, no additional data)
        let _req =
            McuFipsPeriodicStatusReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

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

    async fn handle_ocp_lock_set_perma_hek<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        if req.len() > size_of::<OcpLockSetPermaHekReq>() {
            return Err(errors::INVALID_PARAMS);
        }

        let status = if self.otp.set_hek_perma().is_err() {
            MbxCmdStatus::Failure
        } else {
            MbxCmdStatus::Complete
        };

        let resp = OcpLockSetPermaHekResp::default();
        let resp = resp.as_bytes();
        resp_buf[..resp.len()].copy_from_slice(resp);
        Ok((&mut resp_buf[..resp.len()], status))
    }

    async fn handle_ocp_lock_rotate_hek<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req = OcpLockRotateHekReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

        let (resp, _) =
            OcpLockRotateHekResp::mut_from_prefix(resp_buf).map_err(|_| errors::INVALID_PARAMS)?;
        *resp = OcpLockRotateHekResp::default();

        let mut seed = [0u8; 32];
        Rng::generate_random_number(&mut seed)
            .await
            .map_err(|_| errors::MCU_MBOX_COMMON)?;

        let status = if self.otp.rotate_hek(req.hek_slot, &seed).is_err() {
            MbxCmdStatus::Failure
        } else {
            MbxCmdStatus::Complete
        };

        Ok((&mut resp_buf[..size_of::<OcpLockRotateHekResp>()], status))
    }
}

/// Map an MCU mailbox `CommandId` to the Caliptra mailbox command code for
/// pure passthrough commands. Returns `None` for commands handled locally.
fn caliptra_passthrough_cmd(cmd: CommandId) -> Option<u32> {
    let code = match cmd {
        CommandId::MC_FIPS_SELF_TEST_START => CaliptraCommandId::SELF_TEST_START,
        CommandId::MC_FIPS_SELF_TEST_GET_RESULTS => CaliptraCommandId::SELF_TEST_GET_RESULTS,
        CommandId::MC_SHA_INIT => CaliptraCommandId::CM_SHA_INIT,
        CommandId::MC_SHA_UPDATE => CaliptraCommandId::CM_SHA_UPDATE,
        CommandId::MC_SHA_FINAL => CaliptraCommandId::CM_SHA_FINAL,
        CommandId::MC_HMAC => CaliptraCommandId::CM_HMAC,
        CommandId::MC_HMAC_KDF_COUNTER => CaliptraCommandId::CM_HMAC_KDF_COUNTER,
        CommandId::MC_HKDF_EXTRACT => CaliptraCommandId::CM_HKDF_EXTRACT,
        CommandId::MC_HKDF_EXPAND => CaliptraCommandId::CM_HKDF_EXPAND,
        CommandId::MC_IMPORT => CaliptraCommandId::CM_IMPORT,
        CommandId::MC_DELETE => CaliptraCommandId::CM_DELETE,
        CommandId::MC_CM_STATUS => CaliptraCommandId::CM_STATUS,
        CommandId::MC_RANDOM_GENERATE => CaliptraCommandId::CM_RANDOM_GENERATE,
        CommandId::MC_RANDOM_STIR => CaliptraCommandId::CM_RANDOM_STIR,
        CommandId::MC_AES_ENCRYPT_INIT => CaliptraCommandId::CM_AES_ENCRYPT_INIT,
        CommandId::MC_AES_ENCRYPT_UPDATE => CaliptraCommandId::CM_AES_ENCRYPT_UPDATE,
        CommandId::MC_AES_DECRYPT_INIT => CaliptraCommandId::CM_AES_DECRYPT_INIT,
        CommandId::MC_AES_DECRYPT_UPDATE => CaliptraCommandId::CM_AES_DECRYPT_UPDATE,
        CommandId::MC_AES_GCM_ENCRYPT_INIT => CaliptraCommandId::CM_AES_GCM_ENCRYPT_INIT,
        CommandId::MC_AES_GCM_ENCRYPT_UPDATE => CaliptraCommandId::CM_AES_GCM_ENCRYPT_UPDATE,
        CommandId::MC_AES_GCM_ENCRYPT_FINAL => CaliptraCommandId::CM_AES_GCM_ENCRYPT_FINAL,
        CommandId::MC_AES_GCM_DECRYPT_INIT => CaliptraCommandId::CM_AES_GCM_DECRYPT_INIT,
        CommandId::MC_AES_GCM_DECRYPT_UPDATE => CaliptraCommandId::CM_AES_GCM_DECRYPT_UPDATE,
        CommandId::MC_AES_GCM_DECRYPT_FINAL => CaliptraCommandId::CM_AES_GCM_DECRYPT_FINAL,
        CommandId::MC_ECDH_GENERATE => CaliptraCommandId::CM_ECDH_GENERATE,
        CommandId::MC_ECDH_FINISH => CaliptraCommandId::CM_ECDH_FINISH,
        CommandId::MC_ECDSA_CMK_PUBLIC_KEY => CaliptraCommandId::CM_ECDSA_PUBLIC_KEY,
        CommandId::MC_ECDSA_CMK_SIGN => CaliptraCommandId::CM_ECDSA_SIGN,
        CommandId::MC_ECDSA_CMK_VERIFY => CaliptraCommandId::CM_ECDSA_VERIFY,
        CommandId::MC_MLDSA_CMK_PUBLIC_KEY => CaliptraCommandId::CM_MLDSA_PUBLIC_KEY,
        CommandId::MC_MLDSA_CMK_SIGN => CaliptraCommandId::CM_MLDSA_SIGN,
        CommandId::MC_MLDSA_CMK_VERIFY => CaliptraCommandId::CM_MLDSA_VERIFY,
        CommandId::MC_PROD_DEBUG_UNLOCK_REQ => CaliptraCommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ,
        CommandId::MC_PROD_DEBUG_UNLOCK_TOKEN => {
            CaliptraCommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN
        }
        _ => return None,
    };
    Some(code.into())
}
