// Licensed under the Apache-2.0 license

use crate::cert_store::*;
use crate::chunk_ctx::LargeResponseCtx;
use crate::codec::{encode_u8_slice, Codec, MessageBuf};
use crate::commands::error_rsp::{encode_error_response, ErrorCode};
use crate::commands::{
    algorithms_rsp, capabilities_rsp, certificate_rsp, challenge_auth_rsp, chunk_get_rsp,
    digests_rsp, end_session_ack_rsp, finish_rsp, key_exchange_rsp, measurements_rsp,
    vendor_defined_rsp, version_rsp,
};
use crate::error::*;
use crate::measurements::SpdmMeasurements;
use crate::protocol::algorithms::*;
use crate::protocol::common::{ReqRespCode, SpdmMsgHdr};
use crate::protocol::version::*;
use crate::protocol::DeviceCapabilities;
use crate::session::{SessionManager, SessionState};
use crate::state::{ConnectionState, State};
use crate::transcript::{Transcript, TranscriptContext};
use crate::transport::common::SpdmTransport;
use crate::vdm_handler::VdmHandler;
use libapi_caliptra::crypto::asym::*;
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;

// Maximum SPDM responder buffer size
#[cfg(feature = "large-buffer")]
pub const MAX_SPDM_RESPONDER_BUF_SIZE: usize = 2048;

#[cfg(not(feature = "large-buffer"))]
pub const MAX_SPDM_RESPONDER_BUF_SIZE: usize = 1024;

pub struct SpdmContext<'a> {
    transport: &'a mut dyn SpdmTransport,
    pub(crate) supported_versions: &'a [SpdmVersion],
    pub(crate) supported_secure_versions: &'a [SpdmVersion],
    pub(crate) state: State,
    pub(crate) shared_transcript: Transcript,
    pub(crate) local_capabilities: DeviceCapabilities,
    pub(crate) local_algorithms: LocalDeviceAlgorithms<'a>,
    pub(crate) device_certs_store: &'a dyn SpdmCertStore,
    pub(crate) measurements: SpdmMeasurements<'a>,
    pub(crate) large_resp_context: LargeResponseCtx,
    pub(crate) session_mgr: SessionManager,
    pub(crate) vdm_handlers: Option<&'a mut [&'a mut dyn VdmHandler]>,
}

impl<'a> SpdmContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        supported_versions: &'a [SpdmVersion],
        supported_secure_versions: &'a [SpdmVersion],
        spdm_transport: &'a mut dyn SpdmTransport,
        local_capabilities: DeviceCapabilities,
        local_algorithms: LocalDeviceAlgorithms<'a>,
        device_certs_store: &'a dyn SpdmCertStore,
        measurements: SpdmMeasurements<'a>,
        vdm_handlers: Option<&'a mut [&'a mut dyn VdmHandler]>,
    ) -> SpdmResult<Self> {
        validate_supported_versions(supported_versions)?;

        validate_cert_store(device_certs_store)?;

        Ok(Self {
            supported_versions,
            supported_secure_versions,
            transport: spdm_transport,
            state: State::new(),
            shared_transcript: Transcript::new(),
            local_capabilities,
            local_algorithms,
            device_certs_store,
            measurements,
            large_resp_context: LargeResponseCtx::default(),
            session_mgr: SessionManager::new(),
            vdm_handlers,
        })
    }

    pub async fn process_message(&mut self, msg_buf: &mut MessageBuf<'a>) -> SpdmResult<()> {
        let secure = self
            .transport
            .receive_request(msg_buf)
            .await
            .map_err(SpdmError::Transport)?;

        // Reset active session_id
        self.session_mgr.reset_active_session_id();

        if secure {
            // Create a temporary buffer for decrypted application data
            let mut app_data = [0u8; MAX_SPDM_RESPONDER_BUF_SIZE];
            let app_data_len = self
                .session_mgr
                .decode_secure_message(self.transport, msg_buf, &mut app_data)
                .await
                .map_err(SpdmError::Session)?;

            // Replace msg_buf contents with the decrypted application data
            msg_buf.reset();

            // Copy decrypted data into msg_buf using encode_u8_slice
            encode_u8_slice(&app_data[..app_data_len], msg_buf).map_err(SpdmError::Codec)?;
            msg_buf.push_data(app_data_len).map_err(SpdmError::Codec)?;
        }

        // Process message
        match self.handle_request(msg_buf).await {
            Ok(()) => {
                self.send_response(msg_buf, secure).await?;
            }
            Err((rsp, command_error)) => {
                if rsp {
                    self.send_response(msg_buf, secure)
                        .await
                        .inspect_err(|_| {})?;
                }
                Err(SpdmError::Command(command_error))?;
            }
        }

        Ok(())
    }

    async fn handle_request(&mut self, buf: &mut MessageBuf<'a>) -> CommandResult<()> {
        let req = buf;

        let req_msg_header: SpdmMsgHdr =
            SpdmMsgHdr::decode(req).map_err(|e| (false, CommandError::Codec(e)))?;

        let req_code = req_msg_header
            .req_resp_code()
            .map_err(|_| (false, CommandError::UnsupportedRequest))?;

        if req_code != ReqRespCode::ChunkGet && self.large_resp_context.in_progress() {
            // Reset large response context if the request is not a CHUNK_GET
            self.large_resp_context.reset();
        }

        // Check for requests prohibited within session
        self.validate_request_in_session_context(req_code, req)?;

        match req_code {
            ReqRespCode::GetVersion => {
                version_rsp::handle_get_version(self, req_msg_header, req).await?
            }
            ReqRespCode::GetCapabilities => {
                capabilities_rsp::handle_get_capabilities(self, req_msg_header, req).await?
            }
            ReqRespCode::NegotiateAlgorithms => {
                algorithms_rsp::handle_negotiate_algorithms(self, req_msg_header, req).await?
            }
            ReqRespCode::GetDigests => {
                digests_rsp::handle_get_digests(self, req_msg_header, req).await?
            }
            ReqRespCode::GetCertificate => {
                certificate_rsp::handle_get_certificate(self, req_msg_header, req).await?
            }
            ReqRespCode::Challenge => {
                challenge_auth_rsp::handle_challenge(self, req_msg_header, req).await?
            }
            ReqRespCode::GetMeasurements => {
                measurements_rsp::handle_get_measurements(self, req_msg_header, req).await?
            }
            ReqRespCode::ChunkGet => {
                chunk_get_rsp::handle_chunk_get(self, req_msg_header, req).await?
            }
            ReqRespCode::KeyExchange => {
                key_exchange_rsp::handle_key_exchange(self, req_msg_header, req).await?
            }
            ReqRespCode::Finish => finish_rsp::handle_finish(self, req_msg_header, req).await?,
            ReqRespCode::EndSession => {
                end_session_ack_rsp::handle_end_session(self, req_msg_header, req).await?
            }
            ReqRespCode::VendorDefinedRequest => {
                vendor_defined_rsp::handle_vendor_defined_request(self, req_msg_header, req).await?
            }
            _ => Err((false, CommandError::UnsupportedRequest))?,
        }
        Ok(())
    }

    async fn send_response(&mut self, resp: &mut MessageBuf<'a>, secure: bool) -> SpdmResult<()> {
        if secure {
            let mut secure_message = [0u8; MAX_SPDM_RESPONDER_BUF_SIZE];
            let mut secure_message_buf = MessageBuf::new(&mut secure_message);
            let app_data_len = resp.data_len();
            let app_data = resp.data(app_data_len).map_err(SpdmError::Codec)?;

            self.prepare_response_buffer(&mut secure_message_buf)
                .map_err(|_| SpdmError::BufferTooSmall)?;
            self.session_mgr
                .encode_secure_message(self.transport, app_data, &mut secure_message_buf)
                .await
                .map_err(SpdmError::Session)?;
            self.transport
                .send_response(&mut secure_message_buf, secure)
                .await
                .map_err(SpdmError::Transport)
        } else {
            // Send response without encryption
            self.transport
                .send_response(resp, secure)
                .await
                .map_err(SpdmError::Transport)
        }
    }

    pub(crate) fn reset(&mut self) {
        self.state.reset();
        self.session_mgr.reset();
    }

    pub(crate) fn prepare_response_buffer(&self, rsp_buf: &mut MessageBuf) -> CommandResult<()> {
        rsp_buf.reset();
        rsp_buf
            .reserve(self.transport.header_size())
            .map_err(|_| (false, CommandError::BufferTooSmall))?;
        Ok(())
    }

    pub(crate) fn generate_error_response(
        &self,
        msg_buf: &mut MessageBuf,
        error_code: ErrorCode,
        error_data: u8,
        extended_data: Option<&[u8]>,
    ) -> (bool, CommandError) {
        let _ = self
            .prepare_response_buffer(msg_buf)
            .map_err(|_| (false, CommandError::BufferTooSmall));
        let spdm_version = self.state.connection_info.version_number();

        encode_error_response(msg_buf, spdm_version, error_code, error_data, extended_data)
    }

    /// Returns the minimum data transfer size based on local and peer capabilities.
    pub(crate) fn min_data_transfer_size(&self) -> usize {
        self.local_capabilities.data_transfer_size.min(
            self.state
                .connection_info
                .peer_capabilities()
                .data_transfer_size,
        ) as usize
    }

    pub(crate) fn support_large_msg_chunking(&self) -> bool {
        // Chunking is only supported from SPDM v1.2 onwards
        // and both the Responder and the Requester must support chunking.
        self.state.connection_info.version_number() >= SpdmVersion::V12
            && self.local_capabilities.flags.chunk_cap() == 1
            && self
                .state
                .connection_info
                .peer_capabilities()
                .flags
                .chunk_cap()
                == 1
    }

    pub(crate) fn reset_transcript_via_req_code(&mut self, req_code: ReqRespCode) {
        // Any request other than GET_MEASUREMENTS resets the L1 transcript context.
        if req_code != ReqRespCode::GetMeasurements {
            self.shared_transcript.reset_context(TranscriptContext::L1);
        }

        // If requester issued GET_MEASUREMENTS or KEY_EXCHANGE or FINISH request
        // and skipped CHALLENGE completion, reset M1 context.
        match req_code {
            ReqRespCode::GetMeasurements
            | ReqRespCode::KeyExchange
            | ReqRespCode::Finish
            | ReqRespCode::EndSession => {
                if self.state.connection_info.state() < ConnectionState::Authenticated {
                    self.shared_transcript.reset_context(TranscriptContext::M1);
                }
            }
            ReqRespCode::GetDigests => {
                self.shared_transcript.reset_context(TranscriptContext::M1);
            }
            _ => {}
        }
    }

    pub(crate) async fn append_message_to_transcript(
        &mut self,
        msg_buf: &mut MessageBuf<'_>,
        transcript_context: TranscriptContext,
        session_id: Option<u32>,
    ) -> CommandResult<()> {
        let data_offset = msg_buf.data_offset();

        let msg = msg_buf
            .message_slice(data_offset)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        self.append_slice_to_transcript(msg, transcript_context, session_id)
            .await
    }

    pub(crate) async fn append_slice_to_transcript(
        &mut self,
        data: &[u8],
        transcript_context: TranscriptContext,
        session_id: Option<u32>,
    ) -> CommandResult<()> {
        let session_info = if let Some(session_id) = session_id {
            Some(
                self.session_mgr
                    .session_info_mut(session_id)
                    .map_err(|e| (false, CommandError::Session(e)))?,
            )
        } else {
            None
        };

        self.shared_transcript
            .append(transcript_context, session_info, data)
            .await
            .map_err(|e| (false, CommandError::Transcript(e)))
    }

    pub(crate) async fn transcript_hash(
        &mut self,
        transcript_context: TranscriptContext,
        session_id: Option<u32>,
        finish_hash: bool,
    ) -> CommandResult<[u8; SHA384_HASH_SIZE]> {
        let mut transcript_hash = [0u8; SHA384_HASH_SIZE];
        let session_info = if let Some(session_id) = session_id {
            Some(
                self.session_mgr
                    .session_info_mut(session_id)
                    .map_err(|e| (false, CommandError::Session(e)))?,
            )
        } else {
            None
        };

        self.shared_transcript
            .hash(
                transcript_context,
                session_info,
                &mut transcript_hash,
                finish_hash,
            )
            .await
            .map_err(|e| (false, CommandError::Transcript(e)))?;

        Ok(transcript_hash)
    }

    /// Validates that the SPDM header version matches the negotiated connection version
    /// Returns the validated connection version on success
    pub(crate) fn validate_spdm_version(
        &self,
        spdm_hdr: &SpdmMsgHdr,
        req_payload: &mut MessageBuf,
    ) -> CommandResult<SpdmVersion> {
        let connection_version = self.state.connection_info.version_number();
        match spdm_hdr.version() {
            Ok(version) if version == connection_version => Ok(connection_version),
            _ => {
                Err(self.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None))
            }
        }
    }

    pub(crate) fn validate_negotiated_hash_algo(
        &mut self,
        rsp: &mut MessageBuf,
    ) -> CommandResult<()> {
        let peer_algorithms = self.state.connection_info.peer_algorithms();
        let local_algorithms = &self.local_algorithms.device_algorithms;
        let algorithm_priority_table = &self.local_algorithms.algorithm_priority_table;

        let base_hash_sel = local_algorithms.base_hash_algo.prioritize(
            &peer_algorithms.base_hash_algo,
            algorithm_priority_table.base_hash_algo,
        );

        // Ensure BaseHashSel has exactly one bit set and it is SHA-384
        if base_hash_sel.0.count_ones() != 1 || base_hash_sel.tpm_alg_sha_384() != 1 {
            return Err(self.generate_error_response(rsp, ErrorCode::Unspecified, 0, None));
        }

        Ok(())
    }

    pub(crate) fn validate_negotiated_base_asym_algo(
        &self,
        req_payload: &mut MessageBuf,
    ) -> CommandResult<AsymAlgo> {
        let peer_algorithms = self.state.connection_info.peer_algorithms();
        let local_algorithms = &self.local_algorithms.device_algorithms;
        let algorithm_priority_table = &self.local_algorithms.algorithm_priority_table;

        let base_asym_sel = BaseAsymAlgo(local_algorithms.base_asym_algo.0.prioritize(
            &peer_algorithms.base_asym_algo.0,
            algorithm_priority_table.base_asym_algo,
        ));

        // Ensure AsymAlgoSel has exactly one bit set and it is ECC P-384
        if base_asym_sel.0.count_ones() != 1 || base_asym_sel.tpm_alg_ecdsa_ecc_nist_p384() != 1 {
            return Err(self.generate_error_response(
                req_payload,
                ErrorCode::InvalidRequest,
                0,
                None,
            ));
        }

        Ok(AsymAlgo::EccP384)
    }

    pub(crate) fn validate_negotiated_dhe_group(&self, rsp: &mut MessageBuf) -> CommandResult<()> {
        let peer_algorithms = self.state.connection_info.peer_algorithms();
        let local_algorithms = &self.local_algorithms.device_algorithms;
        let algorithm_priority_table = &self.local_algorithms.algorithm_priority_table;

        let dhe_group_sel = DheNamedGroup(local_algorithms.dhe_group.0.prioritize(
            &peer_algorithms.dhe_group.0,
            algorithm_priority_table.dhe_group,
        ));

        // Ensure DheGroupSel has exactly one bit set and it is SECP384R1
        if dhe_group_sel.0.count_ones() != 1 || dhe_group_sel.secp384r1() != 1 {
            return Err(self.generate_error_response(rsp, ErrorCode::Unspecified, 0, None));
        }

        Ok(())
    }

    /// Validates that the request is allowed in the current session context.
    /// Certain requests are prohibited when an active session exists.
    fn validate_request_in_session_context(
        &self,
        req_code: ReqRespCode,
        req: &mut MessageBuf<'a>,
    ) -> CommandResult<()> {
        let Some(session_id) = self.session_mgr.active_session_id() else {
            return Ok(());
        };

        let session_info = self
            .session_mgr
            .session_info(session_id)
            .map_err(|_| self.generate_error_response(req, ErrorCode::SessionRequired, 0, None))?;

        match req_code {
            // These requests are completely prohibited within any session
            ReqRespCode::GetVersion
            | ReqRespCode::GetCapabilities
            | ReqRespCode::NegotiateAlgorithms
            | ReqRespCode::Challenge
            | ReqRespCode::KeyExchange => {
                Err(self.generate_error_response(req, ErrorCode::UnexpectedRequest, 0, None))
            }

            // These requests require established session state (Application phase)
            ReqRespCode::GetDigests
            | ReqRespCode::GetCertificate
            | ReqRespCode::GetMeasurements
            | ReqRespCode::EndSession => {
                if session_info.session_state == SessionState::Established {
                    Ok(())
                } else {
                    Err(self.generate_error_response(req, ErrorCode::UnexpectedRequest, 0, None))
                }
            }

            // FINISH requires handshake in progress state (Session Handshake phase)
            ReqRespCode::Finish => {
                if session_info.session_state == SessionState::HandshakeInProgress {
                    Ok(())
                } else {
                    Err(self.generate_error_response(req, ErrorCode::UnexpectedRequest, 0, None))
                }
            }

            // All other requests are allowed in any session state
            _ => Ok(()),
        }
    }
}
