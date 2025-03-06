// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::commands::error_rsp::{fill_error_response, ErrorCode};
use crate::commands::{capabilities_rsp, version_rsp};
use crate::error::*;
use crate::protocol::common::{ReqRespCode, SpdmMsgHdr};
use crate::protocol::version::SpdmVersion;
use crate::protocol::{DeviceCapabilities, MAX_NUM_SUPPORTED_SPDM_VERSIONS, MAX_SUPORTED_VERSION};
use crate::state::State;
use crate::transport::MctpTransport;
use libtock_platform::Syscalls;

pub struct SpdmContext<'a, S: Syscalls> {
    transport: &'a mut MctpTransport<S>,
    pub(crate) supported_versions: &'a [SpdmVersion],
    pub(crate) state: State,
    pub(crate) local_capabilities: DeviceCapabilities,
}

impl<'a, S: Syscalls> SpdmContext<'a, S> {
    pub fn new(
        supported_versions: &'a [SpdmVersion],
        spdm_transport: &'a mut MctpTransport<S>,
        local_capabilities: DeviceCapabilities,
    ) -> SpdmResult<Self> {
        if supported_versions.is_empty()
            || supported_versions.len() > MAX_NUM_SUPPORTED_SPDM_VERSIONS
            || supported_versions.iter().any(|v| *v > MAX_SUPORTED_VERSION)
        {
            Err(SpdmError::InvalidParam)?;
        }

        Ok(Self {
            supported_versions,
            transport: spdm_transport,
            state: State::new(),
            local_capabilities,
        })
    }

    pub async fn process_message(&mut self, msg_buf: &mut MessageBuf<'a>) -> SpdmResult<()> {
        self.transport
            .receive_request(msg_buf)
            .await
            .inspect_err(|_| {})?;

        // Process message
        match self.handle_request(msg_buf) {
            Ok(resp_code) => {
                self.send_response(resp_code, msg_buf)
                    .await
                    .inspect_err(|_| {})?;
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

    fn handle_request(&mut self, buf: &mut MessageBuf<'a>) -> CommandResult<ReqRespCode> {
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
        spdm_resp_hdr.encode(resp)?;

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
}
