// Licensed under the Apache-2.0 license

use crate::cert_store::*;
use crate::chunk_ctx::LargeResponseCtx;
use crate::codec::{Codec, MessageBuf};
use crate::commands::error_rsp::{encode_error_response, ErrorCode};
use crate::commands::{
    algorithms_rsp, capabilities_rsp, certificate_rsp, challenge_auth_rsp, chunk_get_rsp,
    digests_rsp, measurements_rsp, version_rsp,
};
use crate::error::*;
use crate::measurements::common::SpdmMeasurements;
use crate::protocol::algorithms::*;
use crate::protocol::common::{ReqRespCode, SpdmMsgHdr};
use crate::protocol::version::*;
use crate::protocol::DeviceCapabilities;
use crate::state::{ConnectionState, State};
use crate::transcript::{TranscriptContext, TranscriptManager};
use crate::transport::common::SpdmTransport;

pub struct SpdmContext<'a> {
    transport: &'a mut dyn SpdmTransport,
    pub(crate) supported_versions: &'a [SpdmVersion],
    pub(crate) state: State,
    pub(crate) transcript_mgr: TranscriptManager,
    pub(crate) local_capabilities: DeviceCapabilities,
    pub(crate) local_algorithms: LocalDeviceAlgorithms<'a>,
    pub(crate) device_certs_store: &'a dyn SpdmCertStore,
    pub(crate) measurements: SpdmMeasurements,
    pub(crate) large_resp_context: LargeResponseCtx,
}

impl<'a> SpdmContext<'a> {
    pub fn new(
        supported_versions: &'a [SpdmVersion],
        spdm_transport: &'a mut dyn SpdmTransport,
        local_capabilities: DeviceCapabilities,
        device_certs_store: &'a dyn SpdmCertStore,
    ) -> SpdmResult<Self> {
        validate_supported_versions(supported_versions)?;

        validate_cert_store(device_certs_store)?;

        Ok(Self {
            supported_versions,
            transport: spdm_transport,
            state: State::new(),
            transcript_mgr: TranscriptManager::new(),
            local_capabilities,
            local_algorithms: LocalDeviceAlgorithms::default(),
            device_certs_store,
            measurements: SpdmMeasurements::default(),
            large_resp_context: LargeResponseCtx::default(),
        })
    }

    pub async fn process_message(&mut self, msg_buf: &mut MessageBuf<'a>) -> SpdmResult<()> {
        let secure = self
            .transport
            .receive_request(msg_buf)
            .await
            .map_err(SpdmError::Transport)?;

        // TODO: Decrypt if secure.

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

            _ => Err((false, CommandError::UnsupportedRequest))?,
        }
        Ok(())
    }

    async fn send_response(&mut self, resp: &mut MessageBuf<'a>, secure: bool) -> SpdmResult<()> {
        // TODO: Encrypt if secure.
        self.transport
            .send_response(resp, secure)
            .await
            .map_err(SpdmError::Transport)
    }

    pub(crate) fn prepare_response_buffer(&self, rsp_buf: &mut MessageBuf) -> CommandResult<()> {
        rsp_buf.reset();
        rsp_buf
            .reserve(self.transport.header_size())
            .map_err(|_| (false, CommandError::BufferTooSmall))?;
        Ok(())
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

    pub(crate) fn verify_selected_hash_algo(&mut self) -> SpdmResult<()> {
        let peer_algorithms = self.state.connection_info.peer_algorithms();
        let local_algorithms = &self.local_algorithms.device_algorithms;
        let algorithm_priority_table = &self.local_algorithms.algorithm_priority_table;

        let base_hash_sel = local_algorithms.base_hash_algo.prioritize(
            &peer_algorithms.base_hash_algo,
            algorithm_priority_table.base_hash_algo,
        );

        // Ensure BaseHashSel has exactly one bit set
        if base_hash_sel.0.count_ones() != 1 {
            return Err(SpdmError::InvalidParam);
        }

        if base_hash_sel.tpm_alg_sha_384() != 1 {
            return Err(SpdmError::InvalidParam);
        }

        Ok(())
    }

    pub(crate) fn selected_base_asym_algo(&self) -> SpdmResult<AsymAlgo> {
        let peer_algorithms = self.state.connection_info.peer_algorithms();
        let local_algorithms = &self.local_algorithms.device_algorithms;
        let algorithm_priority_table = &self.local_algorithms.algorithm_priority_table;

        let base_asym_sel = BaseAsymAlgo(local_algorithms.base_asym_algo.0.prioritize(
            &peer_algorithms.base_asym_algo.0,
            algorithm_priority_table.base_asym_algo,
        ));

        // Ensure AsymAlgoSel has exactly one bit set
        if base_asym_sel.0.count_ones() != 1 || base_asym_sel.tpm_alg_ecdsa_ecc_nist_p384() != 1 {
            return Err(SpdmError::InvalidParam);
        }

        Ok(AsymAlgo::EccP384)
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

    pub(crate) fn reset_transcript_via_req_code(&mut self, req_code: ReqRespCode) {
        // Any request other than GET_MEASUREMENTS resets the L1 transcript context.
        if req_code != ReqRespCode::GetMeasurements {
            self.transcript_mgr.reset_context(TranscriptContext::L1);
        }

        // If requester issued GET_MEASUREMENTS request and skipped CHALLENGE completion, reset M1 context.
        match req_code {
            ReqRespCode::GetMeasurements => {
                if self.state.connection_info.state() < ConnectionState::Authenticated {
                    self.transcript_mgr.reset_context(TranscriptContext::M1);
                }
            }
            ReqRespCode::GetDigests => {
                self.transcript_mgr.reset_context(TranscriptContext::M1);
            }
            _ => {}
        }
    }

    pub(crate) async fn append_message_to_transcript(
        &mut self,
        msg_buf: &mut MessageBuf<'_>,
        transcript_context: TranscriptContext,
    ) -> CommandResult<()> {
        let data_offset = msg_buf.data_offset();

        let msg = msg_buf
            .message_slice(data_offset)
            .map_err(|e| (false, CommandError::Codec(e)))?;

        self.transcript_mgr
            .append(transcript_context, msg)
            .await
            .map_err(|e| (false, CommandError::Transcript(e)))
    }
}
