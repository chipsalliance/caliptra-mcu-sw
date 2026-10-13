// Licensed under the Apache-2.0 license

use crate::errors;
use crate::transport::McuMboxTransport;
#[cfg(feature = "device-ownership-transfer")]
use caliptra_mcu_common_commands::command::execute_dot;
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_common_commands::command::execute_ocp_lock;
use caliptra_mcu_common_commands::command::{execute_authorized, CommandPolicy, CommandResponse};
use caliptra_mcu_common_commands::{
    AsymAlgo, CaliptraCmdHandler, CaliptraCompletionCode, CommandAuthorizer, DebugUnlockChallenge,
    DeviceCapabilities, EvidenceFormat, FirmwareVersion, GetLogResult, PkiEntitySlot,
    EVIDENCE_FORMAT_QUERY,
};
use caliptra_mcu_libsyscall_caliptra::mcu_mbox::MbxCmdStatus;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_mbox_common::messages::{
    ClearLogReq, ClearLogResp, CommandId, DeviceCapsReq, DeviceCapsResp, DpeSignerContextCertReq,
    EndorsementAlgorithm, FirmwareVersionReq, FirmwareVersionResp, FuseReadResp, GetAttestationReq,
    GetAuthCmdChallengeResp, GetDpeCertChainReq, GetLogReq, LogType, MailboxReqHeader,
    MailboxRespHeader, MailboxRespHeaderVarSize, McuMailboxReq, McuMailboxResp,
    McuProdDebugUnlockReqReq, McuProdDebugUnlockReqResp, McuProdDebugUnlockTokenReq,
    McuResponseVarSize, DEVICE_CAPS_SIZE, GET_ATTESTATION_RESP_PREFIX_LEN, MAX_FW_VERSION_STR_LEN,
    MAX_RESP_DATA_SIZE,
};
#[cfg(feature = "attested-csr")]
use caliptra_mcu_mbox_common::messages::{
    ExportAttestedCsrReq, ExportAttestedCsrResp, MAX_ATTESTED_CSR_RESP_DATA_SIZE,
};

use caliptra_mcu_libtock_console::Console;
#[cfg(feature = "device-ownership-transfer")]
use caliptra_mcu_mbox_common::messages::GetDotBackupBlobResp;
#[cfg(feature = "ocp-lock")]
use caliptra_mcu_mbox_common::messages::OcpLockEnumerateHpkeHandlesResp;
#[cfg(feature = "periodic-fips-self-test")]
use caliptra_mcu_mbox_common::messages::{
    McuFipsPeriodicEnableReq, McuFipsPeriodicEnableResp, McuFipsPeriodicStatusReq,
    McuFipsPeriodicStatusResp,
};
use caliptra_mcu_scratch_alloc::BitmapAllocator;
use caliptra_mcu_userlog::{log_info, Hex32};

#[allow(unused_imports)]
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};
use mcu_caliptra_api::{raw, ScratchAlloc};
use mcu_error::{McuErrorCode, McuResult};
use zerocopy::{FromBytes, IntoBytes};

fn map_common_cmd_error(error: CaliptraCompletionCode) -> McuErrorCode {
    match error {
        CaliptraCompletionCode::InvalidParameter => errors::INVALID_PARAMS,
        CaliptraCompletionCode::InvalidLength | CaliptraCompletionCode::InvalidPayloadSize => {
            errors::INVALID_PARAMS
        }
        CaliptraCompletionCode::AccessDenied => errors::UNAUTHORIZED_COMMAND,
        CaliptraCompletionCode::UnsupportedOperation => errors::UNSUPPORTED_COMMAND,
        _ => errors::MCU_MBOX_COMMON,
    }
}

#[derive(Clone, Copy)]
enum CommonResponseFrame {
    Header,
    Challenge,
    Variable,
    ResetRequired,
}

fn request_id(request: &[u8], offset: usize) -> McuResult<u32> {
    let bytes = request
        .get(offset..offset + size_of::<u32>())
        .ok_or(errors::INVALID_PARAMS)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| errors::INVALID_PARAMS)?,
    ))
}

fn authorized_response_frame(request: &[u8]) -> McuResult<CommonResponseFrame> {
    let target = request_id(request, 0)?;
    if target == CommandId::MC_GET_AUTH_CMD_CHALLENGE.0 {
        return Ok(CommonResponseFrame::Challenge);
    }
    if target == CommandId::MC_FUSE_READ.0 {
        return Ok(CommonResponseFrame::Variable);
    }
    if target == CommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0 {
        let subcommand = request_id(request, size_of::<u32>())?;
        return if subcommand == CommandId::MC_GET_DOT_BACKUP_BLOB.0 {
            Ok(CommonResponseFrame::Header)
        } else {
            Ok(CommonResponseFrame::ResetRequired)
        };
    }
    Ok(CommonResponseFrame::Header)
}

/// Command interface for handling MCU mailbox commands.
pub struct CmdInterface<'a, H: CaliptraCmdHandler, A: CommandAuthorizer> {
    transport: &'a mut McuMboxTransport,
    non_crypto_cmds_handler: &'a H,
    cmd_authorizer: &'a mut A,
    scratch: &'a BitmapAllocator,
    busy: AtomicBool,
}

impl<'a, H: CaliptraCmdHandler, A: CommandAuthorizer> CmdInterface<'a, H, A> {
    pub fn new(
        transport: &'a mut McuMboxTransport,
        non_crypto_cmds_handler: &'a H,
        cmd_authorizer: &'a mut A,
        scratch: &'a BitmapAllocator,
    ) -> Self {
        Self {
            transport,
            non_crypto_cmds_handler,
            cmd_authorizer,
            scratch,
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
                    populate_response_checksum(resp)?;

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

    pub async fn handle_responder_msg_from_scratch(&mut self) -> McuResult<()> {
        let mut req_buf = self.scratch.alloc_bytes(size_of::<McuMailboxReq>())?;
        let (cmd_id, req_len) = match self.transport.receive_request(&mut req_buf).await {
            Ok((c, slice)) => (c, slice.len()),
            Err(_) => {
                let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                return Err(errors::TRANSPORT_ERROR);
            }
        };
        if let Err(err) = req_buf.shrink(req_len) {
            let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
            return Err(err);
        }

        let mut resp_buf = match self
            .scratch
            .alloc_bytes(response_buffer_size::<H>(cmd_id, &req_buf[..req_len]))
        {
            Ok(buf) => buf,
            Err(err) => {
                let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                return Err(err);
            }
        };
        let status = match self
            .process_request(&mut req_buf, req_len, cmd_id, &mut resp_buf)
            .await
        {
            Ok((resp, status)) => {
                if status == MbxCmdStatus::Complete {
                    if resp.len() < size_of::<MailboxRespHeader>() {
                        let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                        return Err(errors::MCU_MBOX_COMMON);
                    }

                    populate_response_checksum(resp)?;

                    self.transport.send_response(resp).await.map_err(|_| {
                        let _ = self.transport.finalize_response(MbxCmdStatus::Failure);
                        errors::TRANSPORT_ERROR
                    })?;
                }
                status
            }
            Err(_) => MbxCmdStatus::Failure,
        };

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
        log_info!(
            Console::<DefaultSyscalls>::writer(),
            "MCU mailbox command called: 0x{}",
            Hex32(cmd)
        );
        let result = if cmd_id.is_vendor_unique() {
            Err(errors::UNSUPPORTED_COMMAND)
        } else if let Some(caliptra_cmd) = caliptra_passthrough_cmd(cmd_id) {
            self.handle_crypto_passthrough(req_buf, req_len, caliptra_cmd, resp_buf)
                .await
        } else {
            let req = req_buf.get(..req_len).ok_or(errors::INVALID_PARAMS)?;
            match cmd_id {
                CommandId::MC_FIRMWARE_VERSION => self.handle_fw_version(req, resp_buf).await,
                CommandId::MC_DEVICE_CAPABILITIES => self.handle_device_caps(req, resp_buf).await,
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
                CommandId::MC_AUTHORIZED_COMMAND => {
                    self.handle_authorized_command(req, resp_buf).await
                }
                #[cfg(feature = "ocp-lock")]
                CommandId::MC_OCP_LOCK => self.handle_ocp_lock_command(req, resp_buf).await,
                #[cfg(feature = "device-ownership-transfer")]
                CommandId::MC_DEVICE_OWNERSHIP_TRANSFER => {
                    self.handle_dot_command(req, resp_buf).await
                }
                #[cfg(feature = "attested-csr")]
                CommandId::MC_EXPORT_ATTESTED_CSR => {
                    self.handle_export_attested_csr(req, resp_buf).await
                }
                CommandId::MC_GET_ATTESTATION => self.handle_get_attestation(req, resp_buf).await,
                CommandId::MC_PROD_DEBUG_UNLOCK_REQ => {
                    self.handle_prod_debug_unlock_req(req, resp_buf).await
                }
                CommandId::MC_DPE_SIGNER_CONTEXT_CERT => {
                    self.handle_dpe_signer_context_cert(req, resp_buf).await
                }
                CommandId::MC_GET_DPE_CERTIFICATE_CHAIN => {
                    self.handle_get_dpe_cert_chain(req, resp_buf).await
                }
                CommandId::MC_PROD_DEBUG_UNLOCK_TOKEN => {
                    self.handle_prod_debug_unlock_token(req, resp_buf).await
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
        let _req = GetLogReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

        // Reserve the first 4 bytes of the variable-length payload for the
        // `more_data` flag; the rest is filled by the handler.
        const MORE_DATA_FIELD_LEN: usize = core::mem::size_of::<u32>();
        let (hdr_bytes, data) = resp_buf
            .split_at_mut_checked(size_of::<MailboxRespHeaderVarSize>())
            .ok_or(errors::INVALID_PARAMS)?;
        let data = data
            .get_mut(..MAX_RESP_DATA_SIZE)
            .ok_or(errors::INVALID_PARAMS)?;
        let result = self
            .non_crypto_cmds_handler
            .get_log(LogType::DebugLog as u32, &mut data[MORE_DATA_FIELD_LEN..])
            .await;

        let (mbox_cmd_status, resp_len) = match result {
            Ok(GetLogResult {
                bytes_written,
                more_data,
            }) => {
                let more_data_bytes: u32 = if more_data { 1 } else { 0 };
                data[..MORE_DATA_FIELD_LEN].copy_from_slice(&more_data_bytes.to_le_bytes());
                let hdr = MailboxRespHeaderVarSize {
                    data_len: (MORE_DATA_FIELD_LEN + bytes_written) as u32,
                    ..Default::default()
                };
                hdr_bytes.copy_from_slice(hdr.as_bytes());
                (
                    MbxCmdStatus::Complete,
                    size_of::<MailboxRespHeaderVarSize>() + MORE_DATA_FIELD_LEN + bytes_written,
                )
            }
            Err(_) => {
                let hdr = MailboxRespHeaderVarSize::default();
                hdr_bytes.copy_from_slice(hdr.as_bytes());
                (MbxCmdStatus::Failure, size_of::<MailboxRespHeaderVarSize>())
            }
        };

        Ok((&mut resp_buf[..resp_len], mbox_cmd_status))
    }

    /// Handle `MC_CLEAR_LOG` (0x4D43_4C47).
    async fn handle_clear_log<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let _req = ClearLogReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

        let mbox_cmd_status = match self
            .non_crypto_cmds_handler
            .clear_log(LogType::DebugLog as u32)
            .await
        {
            Ok(()) => MbxCmdStatus::Complete,
            Err(_) => MbxCmdStatus::Failure,
        };

        let resp = ClearLogResp::default();
        let resp_bytes = resp.as_bytes();
        resp_buf[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok((&mut resp_buf[..resp_bytes.len()], mbox_cmd_status))
    }

    #[cfg(feature = "attested-csr")]
    async fn handle_export_attested_csr<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req = ExportAttestedCsrReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

        let (hdr_bytes, data) = resp_buf
            .split_at_mut_checked(size_of::<MailboxRespHeaderVarSize>())
            .ok_or(errors::INVALID_PARAMS)?;
        let (mbox_cmd_status, data_len) =
            match stage_attested_csr(self.non_crypto_cmds_handler, self.scratch, req, data).await {
                Ok(len) => (MbxCmdStatus::Complete, len),
                Err(_) => (MbxCmdStatus::Failure, 0),
            };

        let resp_len = if mbox_cmd_status == MbxCmdStatus::Complete {
            let hdr = MailboxRespHeaderVarSize {
                data_len: data_len as u32,
                ..Default::default()
            };
            hdr_bytes.copy_from_slice(hdr.as_bytes());
            size_of::<MailboxRespHeaderVarSize>() + data_len
        } else {
            let hdr = MailboxRespHeaderVarSize::default();
            hdr_bytes.copy_from_slice(hdr.as_bytes());
            size_of::<MailboxRespHeaderVarSize>()
        };

        Ok((&mut resp_buf[..resp_len], mbox_cmd_status))
    }

    async fn handle_dpe_signer_context_cert<'r>(
        &mut self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req =
            DpeSignerContextCertReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        let header_len = core::mem::size_of::<MailboxRespHeaderVarSize>();
        if resp_buf.len() < header_len {
            return Err(errors::INVALID_PARAMS);
        }

        let profile = match req.algorithm {
            EndorsementAlgorithm::ECDSA_384 => mcu_caliptra_api::DpeProfile::P384Sha384,
            EndorsementAlgorithm::MLDSA_87 => mcu_caliptra_api::DpeProfile::Mldsa87,
            _ => return Err(errors::INVALID_PARAMS),
        };

        let ret = caliptra_mcu_measurement_api::export_cdi_and_stash(
            self.scratch,
            profile,
            &mut resp_buf[header_len..],
        )
        .await;

        let (mbox_cmd_status, cert_len) = match ret {
            Ok(len) => (MbxCmdStatus::Complete, len),
            Err(_) => (MbxCmdStatus::Failure, 0),
        };

        let hdr = MailboxRespHeaderVarSize {
            hdr: MailboxRespHeader {
                chksum: 0,
                fips_status: 0,
            },
            data_len: cert_len as u32,
        };

        resp_buf[..header_len].copy_from_slice(hdr.as_bytes());
        let total_len = header_len + cert_len;
        Ok((&mut resp_buf[..total_len], mbox_cmd_status))
    }

    async fn handle_get_dpe_cert_chain<'r>(
        &mut self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req = GetDpeCertChainReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

        let header_len = core::mem::size_of::<MailboxRespHeaderVarSize>();
        if resp_buf.len() < header_len {
            return Err(errors::INVALID_PARAMS);
        }

        let requested_size = req.size as usize;
        if requested_size > MAX_RESP_DATA_SIZE || resp_buf.len() < header_len + requested_size {
            return Err(errors::INVALID_PARAMS);
        }

        let mut cert_len = 0;
        let mut ret = Ok(());
        while cert_len < requested_size {
            let chunk_len = (requested_size - cert_len).min(mcu_caliptra_api::DPE_MAX_CHUNK_SIZE);
            let chunk = &mut resp_buf[header_len + cert_len..header_len + cert_len + chunk_len];
            match mcu_caliptra_api::dpe_get_cert_chain_chunk(
                self.scratch,
                mcu_caliptra_api::DpeProfile::P384Sha384,
                req.offset + cert_len as u32,
                chunk,
            )
            .await
            {
                Ok(len) => {
                    cert_len += len;
                    if len < chunk_len {
                        break;
                    }
                }
                Err(err) => {
                    ret = Err(err);
                    break;
                }
            }
        }

        let (mbox_cmd_status, cert_len) = match ret {
            Ok(()) => (MbxCmdStatus::Complete, cert_len),
            Err(_) => (MbxCmdStatus::Failure, 0),
        };

        let hdr = MailboxRespHeaderVarSize {
            hdr: MailboxRespHeader {
                chksum: 0,
                fips_status: 0,
            },
            data_len: cert_len as u32,
        };

        resp_buf[..header_len].copy_from_slice(hdr.as_bytes());
        let total_len = header_len + cert_len;
        Ok((&mut resp_buf[..total_len], mbox_cmd_status))
    }

    /// Handles `MC_GET_ATTESTATION`.
    ///
    /// The response body is `[evidence_format:u32][evidence...]`, framed
    /// directly in `resp_buf` so the evidence is never copied.
    ///
    /// A request whose `evidence_format` is [`EVIDENCE_FORMAT_QUERY`] is a
    /// capability query and returns the supported-format bitmap instead of
    /// evidence, mirroring the SPDM VDM transport.
    async fn handle_get_attestation<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req = GetAttestationReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;

        let (hdr_bytes, body) = resp_buf
            .split_at_mut_checked(size_of::<MailboxRespHeaderVarSize>())
            .ok_or(errors::INVALID_PARAMS)?;

        let (mbox_cmd_status, data_len) =
            match stage_attestation(self.non_crypto_cmds_handler, self.scratch, req, body).await {
                Ok(len) => (MbxCmdStatus::Complete, len),
                Err(_) => (MbxCmdStatus::Failure, 0),
            };

        let hdr = MailboxRespHeaderVarSize {
            data_len: data_len as u32,
            ..Default::default()
        };
        hdr_bytes.copy_from_slice(hdr.as_bytes());

        let resp_len = size_of::<MailboxRespHeaderVarSize>() + data_len;
        Ok((&mut resp_buf[..resp_len], mbox_cmd_status))
    }

    async fn handle_prod_debug_unlock_token<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let req =
            McuProdDebugUnlockTokenReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        let (resp, _) =
            MailboxRespHeader::mut_from_prefix(resp_buf).map_err(|_| errors::INVALID_PARAMS)?;

        let status = match self
            .non_crypto_cmds_handler
            .authorize_debug_unlock_token(self.scratch, req.token.as_bytes())
            .await
        {
            Ok(()) => MbxCmdStatus::Complete,
            Err(_) => MbxCmdStatus::Failure,
        };

        *resp = MailboxRespHeader::default();
        let resp_len = resp.as_bytes().len();
        Ok((&mut resp_buf[..resp_len], status))
    }

    async fn handle_prod_debug_unlock_req<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        const REQUEST_LENGTH_DWORDS: u32 = 2;
        const RESPONSE_LENGTH_DWORDS: u32 = 21;

        let req =
            McuProdDebugUnlockReqReq::ref_from_bytes(req).map_err(|_| errors::INVALID_PARAMS)?;
        if req.0.length != REQUEST_LENGTH_DWORDS {
            return Err(errors::INVALID_PARAMS);
        }

        let (resp, _) = McuProdDebugUnlockReqResp::mut_from_prefix(resp_buf)
            .map_err(|_| errors::INVALID_PARAMS)?;
        let mut challenge = DebugUnlockChallenge::default();
        let status = match self
            .non_crypto_cmds_handler
            .request_debug_unlock(self.scratch, req.0.unlock_level, &mut challenge)
            .await
        {
            Ok(()) => {
                resp.0 = Default::default();
                resp.0.length = RESPONSE_LENGTH_DWORDS;
                resp.0
                    .unique_device_identifier
                    .copy_from_slice(&challenge.unique_device_identifier);
                resp.0.challenge.copy_from_slice(&challenge.challenge);
                MbxCmdStatus::Complete
            }
            Err(_) => MbxCmdStatus::Failure,
        };

        let resp_len = resp.as_bytes().len();
        Ok((&mut resp_buf[..resp_len], status))
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

        let status = raw::raw_mailbox_execute(caliptra_cmd_code, req, resp_buf).await;

        match status {
            Ok(resp_len) => Ok((&mut resp_buf[..resp_len], MbxCmdStatus::Complete)),
            Err(_) => Ok((&mut resp_buf[..0], MbxCmdStatus::Failure)),
        }
    }

    async fn handle_authorized_command<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let body = req
            .get(size_of::<MailboxReqHeader>()..)
            .ok_or(errors::INVALID_PARAMS)?;
        let frame = authorized_response_frame(body)?;
        let data_offset = match frame {
            CommonResponseFrame::Challenge | CommonResponseFrame::Variable => {
                size_of::<MailboxRespHeaderVarSize>()
            }
            CommonResponseFrame::Header | CommonResponseFrame::ResetRequired => {
                size_of::<MailboxRespHeader>()
            }
        };
        let output = resp_buf
            .get_mut(data_offset..)
            .ok_or(errors::INVALID_PARAMS)?;
        let response = execute_authorized(
            self.non_crypto_cmds_handler,
            &*self.cmd_authorizer,
            self.scratch,
            body,
            output,
            CommandPolicy::MCI,
        )
        .await
        .map_err(map_common_cmd_error)?;

        match (frame, response) {
            (CommonResponseFrame::Challenge, CommandResponse::Data(len)) => {
                resp_buf[..size_of::<MailboxRespHeaderVarSize>()].fill(0);
                Ok((
                    &mut resp_buf[..size_of::<MailboxRespHeaderVarSize>() + len],
                    MbxCmdStatus::Complete,
                ))
            }
            (CommonResponseFrame::Variable, CommandResponse::Data(len)) => {
                let header = MailboxRespHeaderVarSize {
                    data_len: len as u32,
                    ..Default::default()
                };
                resp_buf[..size_of::<MailboxRespHeaderVarSize>()]
                    .copy_from_slice(header.as_bytes());
                Ok((
                    &mut resp_buf[..size_of::<MailboxRespHeaderVarSize>() + len],
                    MbxCmdStatus::Complete,
                ))
            }
            (CommonResponseFrame::ResetRequired, CommandResponse::ResetRequired) => {
                let header = MailboxRespHeader::default();
                resp_buf[..size_of::<MailboxRespHeader>()].copy_from_slice(header.as_bytes());
                let reset = resp_buf
                    .get_mut(size_of::<MailboxRespHeader>()..size_of::<MailboxRespHeader>() + 4)
                    .ok_or(errors::INVALID_PARAMS)?;
                reset.copy_from_slice(&1u32.to_le_bytes());
                Ok((
                    &mut resp_buf[..size_of::<MailboxRespHeader>() + 4],
                    MbxCmdStatus::Complete,
                ))
            }
            (CommonResponseFrame::Header, CommandResponse::Empty) => {
                let header = MailboxRespHeader::default();
                resp_buf[..size_of::<MailboxRespHeader>()].copy_from_slice(header.as_bytes());
                Ok((
                    &mut resp_buf[..size_of::<MailboxRespHeader>()],
                    MbxCmdStatus::Complete,
                ))
            }
            (CommonResponseFrame::Header, CommandResponse::Data(len)) => {
                let header = MailboxRespHeader::default();
                resp_buf[..size_of::<MailboxRespHeader>()].copy_from_slice(header.as_bytes());
                Ok((
                    &mut resp_buf[..size_of::<MailboxRespHeader>() + len],
                    MbxCmdStatus::Complete,
                ))
            }
            _ => Err(errors::MCU_MBOX_COMMON),
        }
    }

    #[cfg(feature = "ocp-lock")]
    async fn handle_ocp_lock_command<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let body = req
            .get(size_of::<MailboxReqHeader>()..)
            .ok_or(errors::INVALID_PARAMS)?;
        let subcommand = request_id(body, 0)?;
        let variable = subcommand == CommandId::MC_GET_OCP_LOCK_ENDORSEMENT_CERT.0
            || subcommand == CommandId::MC_GET_OCP_LOCK_EPOCH_KEY_REPORT.0;
        let data_offset = if variable {
            size_of::<MailboxRespHeaderVarSize>()
        } else {
            size_of::<MailboxRespHeader>()
        };
        let output = resp_buf
            .get_mut(data_offset..)
            .ok_or(errors::INVALID_PARAMS)?;
        let response = execute_ocp_lock(
            self.non_crypto_cmds_handler,
            self.scratch,
            body,
            output,
            CommandPolicy::MCI,
        )
        .await
        .map_err(map_common_cmd_error)?;
        let CommandResponse::Data(len) = response else {
            return Err(errors::MCU_MBOX_COMMON);
        };
        if variable {
            let header = MailboxRespHeaderVarSize {
                data_len: len as u32,
                ..Default::default()
            };
            resp_buf[..size_of::<MailboxRespHeaderVarSize>()].copy_from_slice(header.as_bytes());
            Ok((
                &mut resp_buf[..size_of::<MailboxRespHeaderVarSize>() + len],
                MbxCmdStatus::Complete,
            ))
        } else {
            let header = MailboxRespHeader::default();
            resp_buf[..size_of::<MailboxRespHeader>()].copy_from_slice(header.as_bytes());
            Ok((
                &mut resp_buf[..size_of::<MailboxRespHeader>() + len],
                MbxCmdStatus::Complete,
            ))
        }
    }

    #[cfg(feature = "device-ownership-transfer")]
    async fn handle_dot_command<'r>(
        &self,
        req: &[u8],
        resp_buf: &'r mut [u8],
    ) -> McuResult<(&'r mut [u8], MbxCmdStatus)> {
        let body = req
            .get(size_of::<MailboxReqHeader>()..)
            .ok_or(errors::INVALID_PARAMS)?;
        let output = resp_buf
            .get_mut(size_of::<MailboxRespHeader>()..)
            .ok_or(errors::INVALID_PARAMS)?;
        let response = execute_dot(self.non_crypto_cmds_handler, self.scratch, body, output)
            .await
            .map_err(map_common_cmd_error)?;
        let header = MailboxRespHeader::default();
        resp_buf[..size_of::<MailboxRespHeader>()].copy_from_slice(header.as_bytes());
        match response {
            CommandResponse::Data(len) => Ok((
                &mut resp_buf[..size_of::<MailboxRespHeader>() + len],
                MbxCmdStatus::Complete,
            )),
            CommandResponse::ResetRequired => {
                let reset = resp_buf
                    .get_mut(size_of::<MailboxRespHeader>()..size_of::<MailboxRespHeader>() + 4)
                    .ok_or(errors::INVALID_PARAMS)?;
                reset.copy_from_slice(&1u32.to_le_bytes());
                Ok((
                    &mut resp_buf[..size_of::<MailboxRespHeader>() + 4],
                    MbxCmdStatus::Complete,
                ))
            }
            CommandResponse::Empty => Ok((
                &mut resp_buf[..size_of::<MailboxRespHeader>()],
                MbxCmdStatus::Complete,
            )),
        }
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
}

/// Map an MCU mailbox `CommandId` to the Caliptra mailbox command code for
/// pure passthrough commands. Returns `None` for commands handled locally.
fn caliptra_passthrough_cmd(cmd: CommandId) -> Option<u32> {
    let code = match cmd {
        CommandId::MC_FIPS_SELF_TEST_START => raw::CMD_SELF_TEST_START,
        CommandId::MC_FIPS_SELF_TEST_GET_RESULTS => raw::CMD_SELF_TEST_GET_RESULTS,
        CommandId::MC_SHA_INIT => raw::CMD_CM_SHA_INIT,
        CommandId::MC_SHA_UPDATE => raw::CMD_CM_SHA_UPDATE,
        CommandId::MC_SHA_FINAL => raw::CMD_CM_SHA_FINAL,
        CommandId::MC_HMAC => raw::CMD_CM_HMAC,
        CommandId::MC_HMAC_KDF_COUNTER => raw::CMD_CM_HMAC_KDF_COUNTER,
        CommandId::MC_HKDF_EXTRACT => raw::CMD_CM_HKDF_EXTRACT,
        CommandId::MC_HKDF_EXPAND => raw::CMD_CM_HKDF_EXPAND,
        CommandId::MC_IMPORT => raw::CMD_CM_IMPORT,
        CommandId::MC_DELETE => raw::CMD_CM_DELETE,
        CommandId::MC_CM_STATUS => raw::CMD_CM_STATUS,
        CommandId::MC_RANDOM_GENERATE => raw::CMD_CM_RANDOM_GENERATE,
        CommandId::MC_RANDOM_STIR => raw::CMD_CM_RANDOM_STIR,
        CommandId::MC_AES_ENCRYPT_INIT => raw::CMD_CM_AES_ENCRYPT_INIT,
        CommandId::MC_AES_ENCRYPT_UPDATE => raw::CMD_CM_AES_ENCRYPT_UPDATE,
        CommandId::MC_AES_DECRYPT_INIT => raw::CMD_CM_AES_DECRYPT_INIT,
        CommandId::MC_AES_DECRYPT_UPDATE => raw::CMD_CM_AES_DECRYPT_UPDATE,
        CommandId::MC_AES_GCM_ENCRYPT_INIT => raw::CMD_CM_AES_GCM_ENCRYPT_INIT,
        CommandId::MC_AES_GCM_ENCRYPT_UPDATE => raw::CMD_CM_AES_GCM_ENCRYPT_UPDATE,
        CommandId::MC_AES_GCM_ENCRYPT_FINAL => raw::CMD_CM_AES_GCM_ENCRYPT_FINAL,
        CommandId::MC_AES_GCM_DECRYPT_INIT => raw::CMD_CM_AES_GCM_DECRYPT_INIT,
        CommandId::MC_AES_GCM_DECRYPT_UPDATE => raw::CMD_CM_AES_GCM_DECRYPT_UPDATE,
        CommandId::MC_AES_GCM_DECRYPT_FINAL => raw::CMD_CM_AES_GCM_DECRYPT_FINAL,
        CommandId::MC_ECDH_GENERATE => raw::CMD_CM_ECDH_GENERATE,
        CommandId::MC_ECDH_FINISH => raw::CMD_CM_ECDH_FINISH,
        CommandId::MC_ECDSA_CMK_PUBLIC_KEY => raw::CMD_CM_ECDSA_PUBLIC_KEY,
        CommandId::MC_ECDSA_CMK_SIGN => raw::CMD_CM_ECDSA_SIGN,
        CommandId::MC_ECDSA_CMK_VERIFY => raw::CMD_CM_ECDSA_VERIFY,
        CommandId::MC_ECDSA384_SIG_VERIFY => raw::CMD_ECDSA384_SIGNATURE_VERIFY,
        #[cfg(not(feature = "disable-lms-sig-verify"))]
        CommandId::MC_LMS_SIG_VERIFY => raw::CMD_LMS_SIGNATURE_VERIFY,
        CommandId::MC_MLDSA_CMK_PUBLIC_KEY => raw::CMD_CM_MLDSA_PUBLIC_KEY,
        CommandId::MC_MLDSA_CMK_SIGN => raw::CMD_CM_MLDSA_SIGN,
        CommandId::MC_MLDSA_CMK_VERIFY => raw::CMD_CM_MLDSA_VERIFY,
        _ => return None,
    };
    Some(code)
}

/// Bytes to allocate for a command's response.
///
/// Generic over the handler because `MC_GET_ATTESTATION` is sized from the
/// evidence generators the build enables rather than from a fixed enum variant.
/// It is deliberately not a [`McuMailboxResp`] variant: that enum sizes *every*
/// command's allocation by its largest variant, so folding attestation in would
/// inflate all of them.
/// The `InvokeDpeRespPrefix` (12 B) + `DeriveContextExportedCdiRespPrefix` (80 B)
/// staged ahead of the leaf certificate when `dpe_derive_context_exported_cdi`
/// receives the response in-place in `resp_buf`.
const DPE_EXPORTED_CDI_IN_PLACE_PREFIX_LEN: usize = 92;

/// Response buffer size for `MC_DPE_SIGNER_CONTEXT_CERT`: the var-size header
/// plus room for `dpe_derive_context_exported_cdi` to stage its response
/// in-place ahead of a `DPE_MAX_LEAF_CERT_SIZE` leaf certificate.
pub const DPE_SIGNER_CONTEXT_CERT_RESP_SIZE: usize = size_of::<MailboxRespHeaderVarSize>()
    + mcu_caliptra_api::DPE_MAX_LEAF_CERT_SIZE
    + DPE_EXPORTED_CDI_IN_PLACE_PREFIX_LEN;

/// Response payload buffer size for `MC_GET_OCP_LOCK_ENDORSEMENT_CERT` and
/// `MC_GET_OCP_LOCK_EPOCH_KEY_REPORT`.
///
/// Must fit both the encoded output (`out_buf`, up to 7,201 B) and the shifted
/// ML-DSA-87 signature (`sig_buf`, 4,627 B) side-by-side after
/// `CaliptraDpeSigner::sign` stages `SignWithExportedMldsaResp` (7,228 B)
/// in-place.
///
/// Public so integrators can size their MCU mailbox scratch pool against
/// this path.
#[cfg(feature = "ocp-lock")]
pub const OCP_LOCK_IN_PLACE_SIGN_RESP_DATA_SIZE: usize = 11_828;

fn response_buffer_size<H: CaliptraCmdHandler>(cmd: u32, req: &[u8]) -> usize {
    #[cfg(not(feature = "ocp-lock"))]
    let _ = req;
    match CommandId::from(cmd) {
        c if c == CommandId::MC_MLDSA_CMK_VERIFY
            || c == CommandId::MC_ECDSA_CMK_VERIFY
            || c == CommandId::MC_ECDSA384_SIG_VERIFY
            || c == CommandId::MC_LMS_SIG_VERIFY
            || c == CommandId::MC_PROD_DEBUG_UNLOCK_TOKEN =>
        {
            size_of::<MailboxRespHeader>()
        }
        c if c == CommandId::MC_AUTHORIZED_COMMAND => {
            let target = req
                .get(size_of::<MailboxReqHeader>()..)
                .and_then(|body| request_id(body, 0).ok());
            match target {
                Some(target) if target == CommandId::MC_GET_AUTH_CMD_CHALLENGE.0 => {
                    size_of::<GetAuthCmdChallengeResp>()
                }
                Some(target) if target == CommandId::MC_FUSE_READ.0 => size_of::<FuseReadResp>(),
                #[cfg(feature = "device-ownership-transfer")]
                Some(target) if target == CommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0 => {
                    size_of::<GetDotBackupBlobResp>()
                }
                _ => size_of::<MailboxRespHeader>() + size_of::<u32>(),
            }
        }
        #[cfg(feature = "ocp-lock")]
        c if c == CommandId::MC_OCP_LOCK => {
            let subcommand = req
                .get(
                    size_of::<MailboxReqHeader>()..size_of::<MailboxReqHeader>() + size_of::<u32>(),
                )
                .and_then(|s| s.first_chunk::<{ size_of::<u32>() }>())
                .map(|b| u32::from_le_bytes(*b));
            match subcommand {
                Some(sub)
                    if sub == CommandId::MC_GET_OCP_LOCK_ENDORSEMENT_CERT.0
                        || sub == CommandId::MC_GET_OCP_LOCK_EPOCH_KEY_REPORT.0 =>
                {
                    size_of::<MailboxRespHeaderVarSize>() + OCP_LOCK_IN_PLACE_SIGN_RESP_DATA_SIZE
                }
                Some(sub) if sub == CommandId::MC_OCP_LOCK_ENUMERATE_HPKE_HANDLES.0 => {
                    size_of::<OcpLockEnumerateHpkeHandlesResp>()
                }
                // Unknown or missing subcommands are rejected by `handle_ocp_lock_command`.
                _ => size_of::<MailboxRespHeader>(),
            }
        }
        c if c == CommandId::MC_DPE_SIGNER_CONTEXT_CERT => DPE_SIGNER_CONTEXT_CERT_RESP_SIZE,
        c if c == CommandId::MC_GET_DPE_CERTIFICATE_CHAIN => {
            size_of::<MailboxRespHeaderVarSize>() + 1024
        }
        #[cfg(feature = "attested-csr")]
        c if c == CommandId::MC_EXPORT_ATTESTED_CSR => size_of::<ExportAttestedCsrResp>(),
        c if c == CommandId::MC_GET_ATTESTATION => size_of::<McuMailboxResp>().max(
            size_of::<MailboxRespHeaderVarSize>()
                + GET_ATTESTATION_RESP_PREFIX_LEN
                + H::MAX_ATTESTATION_EVIDENCE_LEN,
        ),
        #[cfg(feature = "device-ownership-transfer")]
        CommandId::MC_DEVICE_OWNERSHIP_TRANSFER => size_of::<GetDotBackupBlobResp>(),
        _ => size_of::<McuMailboxResp>(),
    }
}

/// Writes the `MC_EXPORT_ATTESTED_CSR` response body into `body` and returns its
/// length.
///
/// A free function rather than a `CmdInterface` method so it can be tested
/// without standing up a transport.
#[cfg(feature = "attested-csr")]
async fn stage_attested_csr<H: CaliptraCmdHandler, Alloc: mcu_caliptra_api::ScratchAlloc>(
    handler: &H,
    alloc: &Alloc,
    req: &ExportAttestedCsrReq,
    body: &mut [u8],
) -> McuResult<usize> {
    let data = body
        .get_mut(..MAX_ATTESTED_CSR_RESP_DATA_SIZE)
        .ok_or(errors::INVALID_PARAMS)?;
    let ret = handler
        .export_attested_csr(alloc, req.device_key_id, req.algorithm, &req.nonce, data)
        .await;
    match ret {
        Ok(len) if len <= MAX_ATTESTED_CSR_RESP_DATA_SIZE => Ok(len),
        _ => Err(errors::INVALID_PARAMS),
    }
}

/// Writes the `MC_GET_ATTESTATION` response body into `body` and returns its
/// length.
///
/// A free function rather than a `CmdInterface` method so it can be tested
/// without standing up a transport.
async fn stage_attestation<H: CaliptraCmdHandler, Alloc: ScratchAlloc>(
    handler: &H,
    alloc: &Alloc,
    req: &GetAttestationReq,
    body: &mut [u8],
) -> McuResult<usize> {
    let (fmt_bytes, rest) = body
        .split_at_mut_checked(GET_ATTESTATION_RESP_PREFIX_LEN)
        .ok_or(errors::BUFFER_TOO_SMALL)?;
    fmt_bytes.copy_from_slice(&req.evidence_format.to_le_bytes());

    if req.evidence_format == EVIDENCE_FORMAT_QUERY {
        let bitmap = rest
            .get_mut(..size_of::<u32>())
            .ok_or(errors::BUFFER_TOO_SMALL)?;
        bitmap.copy_from_slice(&H::SUPPORTED_EVIDENCE_FORMATS.to_le_bytes());
        return Ok(GET_ATTESTATION_RESP_PREFIX_LEN + size_of::<u32>());
    }

    let format =
        EvidenceFormat::try_from(req.evidence_format).map_err(|_| errors::INVALID_PARAMS)?;
    let algorithm = AsymAlgo::try_from(req.algorithm).map_err(|_| errors::INVALID_PARAMS)?;
    let entity =
        PkiEntitySlot::try_from(req.pki_entity_slot).map_err(|_| errors::INVALID_PARAMS)?;

    // Reject pairs this build cannot produce before touching the buffer, so an
    // unsupported request costs nothing.
    let max_len = H::attestation_evidence_len(format, algorithm);
    if max_len == 0 {
        return Err(errors::UNSUPPORTED_COMMAND);
    }

    // Truncated evidence cannot pass signature verification, so refuse rather
    // than emit a `Complete` response with partial evidence.
    let out = rest.get_mut(..max_len).ok_or(errors::BUFFER_TOO_SMALL)?;

    // Callers pass the canonical pool into this helper so every transport
    // instantiates evidence generation over the same allocator type.
    let evidence_len = handler
        .get_attestation(alloc, format, algorithm, entity, &req.nonce, out)
        .await
        .map_err(|_| errors::MCU_MBOX_COMMON)?;

    Ok(GET_ATTESTATION_RESP_PREFIX_LEN + evidence_len)
}

fn populate_response_checksum(resp: &mut [u8]) -> McuResult<()> {
    if resp.len() < size_of::<MailboxRespHeader>() {
        return Err(errors::INVALID_PARAMS);
    }
    let checksum = raw::mailbox_checksum(0, &resp[size_of::<u32>()..]);
    resp[..size_of::<u32>()].copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use caliptra_mcu_mbox_common::messages::MAX_ATTESTATION_RESP_DATA_SIZE;
    use futures::executor::block_on;
    use std::vec;
    use std::vec::Vec;

    const TEST_EAT_LEN: usize = 3059;
    const TEST_QUOTE_MLDSA_LEN: usize = 6388;

    #[test]
    fn request_buffer_fits_largest_authorized_envelope() {
        assert!(
            size_of::<McuMailboxReq>()
                >= size_of::<MailboxReqHeader>()
                    + caliptra_mcu_common_commands::command::MAX_AUTHORIZED_REQUEST_LEN
        );
    }

    struct TestAlloc;

    impl ScratchAlloc for TestAlloc {
        type Buf<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
            Ok(vec![0; len])
        }
    }

    /// Handler advertising both formats, with ML-DSA available only for quotes.
    /// Mirrors the emulator backend: the EAT is ES384-only today.
    struct TestHandler;

    impl CaliptraCmdHandler for TestHandler {
        async fn get_firmware_version(
            &self,
            _index: u32,
            _version: &mut FirmwareVersion,
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            unimplemented!("not exercised by the attestation tests")
        }

        async fn get_device_capabilities(
            &self,
            _capabilities: &mut DeviceCapabilities,
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            unimplemented!("not exercised by the attestation tests")
        }

        async fn export_attested_csr<Alloc: ScratchAlloc>(
            &self,
            _alloc: &Alloc,
            _device_key_id: u32,
            _algorithm: u32,
            _nonce: &[u8; 32],
            _csr_buf: &mut [u8],
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<usize> {
            unimplemented!("not exercised by the attestation tests")
        }

        async fn request_debug_unlock<Alloc: ScratchAlloc>(
            &self,
            _alloc: &Alloc,
            _unlock_level: u8,
            _challenge: &mut DebugUnlockChallenge,
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            unimplemented!("not exercised by the attestation tests")
        }

        async fn authorize_debug_unlock_token<Alloc: ScratchAlloc>(
            &self,
            _alloc: &Alloc,
            _token_data: &[u8],
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            unimplemented!("not exercised by the attestation tests")
        }

        const SUPPORTED_EVIDENCE_FORMATS: u32 =
            EvidenceFormat::OcpEat.bit() | EvidenceFormat::PcrQuote.bit();
        const MAX_ATTESTATION_EVIDENCE_LEN: usize = TEST_QUOTE_MLDSA_LEN;

        fn attestation_evidence_len(format: EvidenceFormat, algorithm: AsymAlgo) -> usize {
            match (format, algorithm) {
                (EvidenceFormat::OcpEat, AsymAlgo::EccP384) => TEST_EAT_LEN,
                (EvidenceFormat::PcrQuote, AsymAlgo::EccP384) => 1840,
                (EvidenceFormat::PcrQuote, AsymAlgo::Mldsa87) => TEST_QUOTE_MLDSA_LEN,
                _ => 0,
            }
        }

        async fn get_attestation<Alloc: ScratchAlloc>(
            &self,
            _alloc: &Alloc,
            format: EvidenceFormat,
            algorithm: AsymAlgo,
            _entity: PkiEntitySlot,
            nonce: &[u8; 32],
            out: &mut [u8],
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<usize> {
            let len = Self::attestation_evidence_len(format, algorithm);
            // Evidence shorter than the reservation is the normal case; fill a
            // recognizable prefix so the test can prove framing offsets.
            let len = len - 8;
            out[..4].copy_from_slice(&(format as u32).to_le_bytes());
            out[4..8].copy_from_slice(&nonce[..4]);
            out[8..len].fill(0xAB);
            Ok(len)
        }
    }

    fn request(format: u32, algorithm: u32) -> GetAttestationReq {
        GetAttestationReq {
            hdr: MailboxReqHeader { chksum: 0 },
            evidence_format: format,
            algorithm,
            pki_entity_slot: PkiEntitySlot::Vendor as u32,
            nonce: [0x5A; 32],
        }
    }

    #[test]
    fn response_buffer_is_sized_from_the_handler_not_a_fixed_variant() {
        let sized = response_buffer_size::<TestHandler>(CommandId::MC_GET_ATTESTATION.0, &[]);
        assert!(
            sized
                >= size_of::<MailboxRespHeaderVarSize>()
                    + GET_ATTESTATION_RESP_PREFIX_LEN
                    + TEST_QUOTE_MLDSA_LEN
        );
        // Other commands must not grow because attestation needs a big buffer.
        assert_eq!(
            response_buffer_size::<TestHandler>(CommandId::MC_FIRMWARE_VERSION.0, &[]),
            size_of::<McuMailboxResp>()
        );
    }

    #[test]
    fn query_returns_the_supported_format_bitmap() {
        let req = request(EVIDENCE_FORMAT_QUERY, 0);
        let mut body = vec![0u8; 64];
        let len = block_on(stage_attestation(&TestHandler, &TestAlloc, &req, &mut body)).unwrap();

        assert_eq!(len, 8);
        assert_eq!(u32::from_le_bytes(body[..4].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(body[4..8].try_into().unwrap()),
            TestHandler::SUPPORTED_EVIDENCE_FORMATS
        );
    }

    #[test]
    fn evidence_is_framed_after_the_echoed_format() {
        let req = request(EvidenceFormat::PcrQuote as u32, AsymAlgo::Mldsa87 as u32);
        let mut body = vec![0u8; MAX_ATTESTATION_RESP_DATA_SIZE];
        let len = block_on(stage_attestation(&TestHandler, &TestAlloc, &req, &mut body)).unwrap();

        assert_eq!(
            len,
            GET_ATTESTATION_RESP_PREFIX_LEN + TEST_QUOTE_MLDSA_LEN - 8
        );
        assert_eq!(
            u32::from_le_bytes(body[..4].try_into().unwrap()),
            EvidenceFormat::PcrQuote as u32
        );
        // Evidence starts immediately after the echoed format, and the nonce
        // reached the generator.
        assert_eq!(
            u32::from_le_bytes(body[4..8].try_into().unwrap()),
            EvidenceFormat::PcrQuote as u32
        );
        assert_eq!(&body[8..12], &[0x5A; 4]);
    }

    #[test]
    fn unsupported_pairs_are_rejected_before_generation() {
        // The EAT is ES384-only today; ML-DSA-87 is not implemented yet.
        let req = request(EvidenceFormat::OcpEat as u32, AsymAlgo::Mldsa87 as u32);
        let mut body = vec![0u8; MAX_ATTESTATION_RESP_DATA_SIZE];
        assert_eq!(
            block_on(stage_attestation(&TestHandler, &TestAlloc, &req, &mut body)),
            Err(errors::UNSUPPORTED_COMMAND)
        );

        // Unknown format and unknown algorithm are parameter errors.
        let req = request(0xFF, AsymAlgo::EccP384 as u32);
        assert_eq!(
            block_on(stage_attestation(&TestHandler, &TestAlloc, &req, &mut body)),
            Err(errors::INVALID_PARAMS)
        );
        let req = request(EvidenceFormat::PcrQuote as u32, 0xFF);
        assert_eq!(
            block_on(stage_attestation(&TestHandler, &TestAlloc, &req, &mut body)),
            Err(errors::INVALID_PARAMS)
        );
    }

    #[test]
    fn a_buffer_too_small_for_the_reservation_fails_instead_of_truncating() {
        let req = request(EvidenceFormat::PcrQuote as u32, AsymAlgo::Mldsa87 as u32);
        // One byte short of the worst case for this pair.
        let mut body = vec![0u8; GET_ATTESTATION_RESP_PREFIX_LEN + TEST_QUOTE_MLDSA_LEN - 1];
        assert_eq!(
            block_on(stage_attestation(&TestHandler, &TestAlloc, &req, &mut body)),
            Err(errors::BUFFER_TOO_SMALL)
        );
    }

    #[cfg(feature = "attested-csr")]
    #[test]
    fn response_buffer_size_for_export_attested_csr_matches_export_attested_csr_resp() {
        let sized = response_buffer_size::<TestHandler>(CommandId::MC_EXPORT_ATTESTED_CSR.0, &[]);
        assert_eq!(sized, size_of::<ExportAttestedCsrResp>());
        assert!(sized >= size_of::<MailboxRespHeaderVarSize>() + MAX_ATTESTED_CSR_RESP_DATA_SIZE);
        assert!(sized > 4096);
    }

    #[cfg(not(feature = "attested-csr"))]
    #[test]
    fn export_attested_csr_reserves_no_large_buffer_without_feature() {
        assert_eq!(
            response_buffer_size::<TestHandler>(CommandId::MC_EXPORT_ATTESTED_CSR.0, &[]),
            size_of::<McuMailboxResp>()
        );
    }

    #[cfg(feature = "attested-csr")]
    struct CsrTestHandler {
        resp_len: usize,
    }

    #[cfg(feature = "attested-csr")]
    impl CaliptraCmdHandler for CsrTestHandler {
        async fn get_firmware_version(
            &self,
            _index: u32,
            _version: &mut FirmwareVersion,
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            unimplemented!()
        }

        async fn get_device_capabilities(
            &self,
            _capabilities: &mut DeviceCapabilities,
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            unimplemented!()
        }

        async fn export_attested_csr<Alloc: ScratchAlloc>(
            &self,
            _alloc: &Alloc,
            _device_key_id: u32,
            _algorithm: u32,
            _nonce: &[u8; 32],
            csr_buf: &mut [u8],
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<usize> {
            if csr_buf.len() < self.resp_len {
                return Err(
                    caliptra_mcu_common_commands::CaliptraCompletionCode::InsufficientResources,
                );
            }
            csr_buf[..self.resp_len].fill(0xEE);
            Ok(self.resp_len)
        }

        async fn request_debug_unlock<Alloc: ScratchAlloc>(
            &self,
            _alloc: &Alloc,
            _unlock_level: u8,
            _challenge: &mut DebugUnlockChallenge,
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            unimplemented!()
        }

        async fn authorize_debug_unlock_token<Alloc: ScratchAlloc>(
            &self,
            _alloc: &Alloc,
            _token_data: &[u8],
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            unimplemented!()
        }

        const SUPPORTED_EVIDENCE_FORMATS: u32 = 0;
        const MAX_ATTESTATION_EVIDENCE_LEN: usize = 0;

        fn attestation_evidence_len(_format: EvidenceFormat, _algorithm: AsymAlgo) -> usize {
            0
        }

        async fn get_attestation<Alloc: ScratchAlloc>(
            &self,
            _alloc: &Alloc,
            _format: EvidenceFormat,
            _algorithm: AsymAlgo,
            _entity: PkiEntitySlot,
            _nonce: &[u8; 32],
            _out: &mut [u8],
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<usize> {
            unimplemented!()
        }
    }

    #[cfg(feature = "attested-csr")]
    #[test]
    fn export_attested_csr_accepts_large_mldsa_discovery_response() {
        const REALISTIC_MLDSA_DISCOVERY_LEN: usize = 4800;
        let handler = CsrTestHandler {
            resp_len: REALISTIC_MLDSA_DISCOVERY_LEN,
        };
        let req = ExportAttestedCsrReq {
            hdr: MailboxReqHeader { chksum: 0 },
            device_key_id: 0,
            algorithm: 2,
            nonce: [0x77; 32],
        };
        let mut body = vec![0u8; MAX_ATTESTED_CSR_RESP_DATA_SIZE];
        let len = block_on(stage_attested_csr(&handler, &TestAlloc, &req, &mut body)).unwrap();
        assert_eq!(len, REALISTIC_MLDSA_DISCOVERY_LEN);
        assert_eq!(&body[..4], &[0xEE; 4]);
    }

    #[cfg(feature = "attested-csr")]
    #[test]
    fn export_attested_csr_accepts_large_mldsa_csr_response() {
        const REALISTIC_MLDSA_CSR_LEN: usize = 12_200;
        let handler = CsrTestHandler {
            resp_len: REALISTIC_MLDSA_CSR_LEN,
        };
        let req = ExportAttestedCsrReq {
            hdr: MailboxReqHeader { chksum: 0 },
            device_key_id: 1,
            algorithm: 2,
            nonce: [0x88; 32],
        };
        let mut body = vec![0u8; MAX_ATTESTED_CSR_RESP_DATA_SIZE];
        let len = block_on(stage_attested_csr(&handler, &TestAlloc, &req, &mut body)).unwrap();
        assert_eq!(len, REALISTIC_MLDSA_CSR_LEN);
        assert_eq!(&body[..4], &[0xEE; 4]);
    }

    #[cfg(feature = "attested-csr")]
    #[test]
    fn export_attested_csr_rejects_oversized_response() {
        let handler = CsrTestHandler {
            resp_len: MAX_ATTESTED_CSR_RESP_DATA_SIZE + 1,
        };
        let req = ExportAttestedCsrReq {
            hdr: MailboxReqHeader { chksum: 0 },
            device_key_id: 0,
            algorithm: 2,
            nonce: [0x77; 32],
        };
        let mut body = vec![0u8; MAX_ATTESTED_CSR_RESP_DATA_SIZE];
        assert_eq!(
            block_on(stage_attested_csr(&handler, &TestAlloc, &req, &mut body)),
            Err(errors::INVALID_PARAMS)
        );
    }
}
