// Licensed under the Apache-2.0 license

use crate::cert_mgr::DeviceCertsManager;
use crate::codec::{Codec, MessageBuf};
use crate::commands::error_rsp::{fill_error_response, ErrorCode};
use crate::commands::{
    algorithms_rsp, capabilities_rsp, certificate_rsp, digests_rsp, version_rsp,
};
use crate::error::*;
use crate::protocol::algorithms::*;
use crate::protocol::common::{ReqRespCode, SpdmMsgHdr};
use crate::protocol::version::*;
use crate::protocol::DeviceCapabilities;
use crate::state::State;
use crate::transport::SpdmTransport;

pub struct SpdmContext<'a> {
    transport: &'a mut dyn SpdmTransport,
    pub(crate) supported_versions: &'a [SpdmVersion],
    pub(crate) state: State,
    pub(crate) local_capabilities: DeviceCapabilities,
    pub(crate) local_algorithms: LocalDeviceAlgorithms<'a>,
    pub(crate) device_certs_manager: &'a DeviceCertsManager,
}

impl<'a> SpdmContext<'a> {
    pub fn new(
        supported_versions: &'a [SpdmVersion],
        spdm_transport: &'a mut dyn SpdmTransport,
        local_capabilities: DeviceCapabilities,
        local_algorithms: LocalDeviceAlgorithms<'a>,
        device_certs_manager: &'a DeviceCertsManager,
    ) -> SpdmResult<Self> {
        validate_supported_versions(supported_versions)?;

        validate_device_algorithms(&local_algorithms)?;

        Ok(Self {
            supported_versions,
            transport: spdm_transport,
            state: State::new(),
            local_capabilities,
            local_algorithms,
            device_certs_manager,
        })
    }

    pub async fn process_message(&mut self, msg_buf: &mut MessageBuf<'a>) -> SpdmResult<()> {
        self.transport
            .receive_request(msg_buf)
            .await
            .map_err(SpdmError::Transport)?;

        // Process message
        match self.handle_request(msg_buf).await {
            Ok(resp_code) => {
                self.send_response(resp_code, msg_buf).await?;
            }
            Err((rsp, command_error)) => {
                if rsp {
                    self.send_response(ReqRespCode::Error, msg_buf)
                        .await
                        .inspect_err(|_| {})?;
                }
                Err(SpdmError::Command(command_error))?;
            }
        }

        Ok(())
    }

    async fn handle_request(&mut self, buf: &mut MessageBuf<'a>) -> CommandResult<ReqRespCode> {
        let req = buf;

        let req_msg_header: SpdmMsgHdr =
            SpdmMsgHdr::decode(req).map_err(|e| (false, CommandError::Codec(e)))?;

        let req_code = req_msg_header
            .req_resp_code()
            .map_err(|_| (false, CommandError::UnsupportedRequest))?;
        let resp_code = req_code
            .response_code()
            .map_err(|_| (false, CommandError::UnsupportedRequest))?;

        match req_code {
            ReqRespCode::GetVersion => version_rsp::handle_version(self, req_msg_header, req)?,
            ReqRespCode::GetCapabilities => {
                capabilities_rsp::handle_capabilities(self, req_msg_header, req)?
            }
            ReqRespCode::NegotiateAlgorithms => {
                algorithms_rsp::handle_negotiate_algorithms(self, req_msg_header, req)?
            }
            ReqRespCode::GetDigests => {
                digests_rsp::handle_digests(self, req_msg_header, req).await?
            }
            ReqRespCode::GetCertificate => {
                certificate_rsp::handle_certificates(self, req_msg_header, req).await?
            }
            _ => Err((false, CommandError::UnsupportedRequest))?,
        }
        Ok(resp_code)
    }

    async fn send_response(
        &mut self,
        resp_code: ReqRespCode,
        resp: &mut MessageBuf<'a>,
    ) -> SpdmResult<()> {
        let spdm_version = self.state.connection_info.version_number();
        let spdm_resp_hdr = SpdmMsgHdr::new(spdm_version, resp_code);
        spdm_resp_hdr.encode(resp).map_err(SpdmError::Codec)?;

        self.transport
            .send_response(resp)
            .await
            .map_err(SpdmError::Transport)
    }

    pub(crate) fn prepare_response_buffer(&self, rsp_buf: &mut MessageBuf) -> CommandResult<()> {
        rsp_buf.reset();
        rsp_buf
            .reserve(self.transport.header_size() + core::mem::size_of::<SpdmMsgHdr>())
            .map_err(|_| (false, CommandError::BufferTooSmall))?;
        Ok(())
    }

    pub fn generate_error_response(
        &self,
        msg_buf: &mut MessageBuf,
        error_code: ErrorCode,
        error_data: u8,
        extended_data: Option<&[u8]>,
    ) -> (bool, CommandError) {
        let _ = self
            .prepare_response_buffer(msg_buf)
            .map_err(|_| (false, CommandError::BufferTooSmall));
        fill_error_response(msg_buf, error_code, error_data, extended_data)
    }

    pub fn get_select_hash_algo(&self) -> SpdmResult<BaseHashAlgoType> {
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

        BaseHashAlgoType::try_from(base_hash_sel.0.trailing_zeros() as u8)
            .map_err(|_| SpdmError::InvalidParam)
    }
}
