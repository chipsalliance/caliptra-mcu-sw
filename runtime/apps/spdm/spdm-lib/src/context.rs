// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::commands::error_rsp::{fill_error_response, ErrorCode};
use crate::commands::version_rsp;
use crate::error::*;
use crate::protocol::{
    ReqRespCode, SpdmMsgHdr, SpdmVersion, MAX_NUM_SUPPORTED_SPDM_VERSIONS, MAX_SUPORTED_VERSION,
};
use crate::state::{ConnectionState, State};
use crate::transport::MctpTransport;
use core::fmt::Write;
use libtock_console::ConsoleWriter;
use libtock_platform::Syscalls;

pub struct SpdmContext<'a, S: Syscalls> {
    supported_versions: &'a [SpdmVersion],
    transport: &'a mut MctpTransport<S>,
    state: State,
    cw: &'a mut ConsoleWriter<S>,
}

impl<'a, S: Syscalls> SpdmContext<'a, S> {
    pub fn new(
        supported_versions: &'a [SpdmVersion],
        spdm_transport: &'a mut MctpTransport<S>,
        cw: &'a mut ConsoleWriter<S>,
    ) -> SpdmResult<Self> {
        if supported_versions.is_empty()
            || supported_versions.len() > MAX_NUM_SUPPORTED_SPDM_VERSIONS
            || supported_versions.iter().any(|v| *v > MAX_SUPORTED_VERSION)
        {
            return Err(SpdmError::InvalidParam);
        }

        Ok(Self {
            supported_versions,
            transport: spdm_transport,
            state: State::new(),
            cw,
        })
    }

    pub async fn process_message(&mut self, msg_buf: &mut MessageBuf<'a>) -> SpdmResult<()> {
        writeln!(self.cw, "SPDM_LIB: Start processing the message").unwrap();

        self.transport
            .receive_request(msg_buf)
            .await
            .inspect_err(|_| {
                writeln!(self.cw, "SPDM_LIB: Failed to receive request").unwrap();
            })?;

        // Process message
        match self.handle_request(msg_buf).await {
            Ok(resp_code) => {
                writeln!(self.cw, "SPDM_LIB: Processed request successfully").unwrap();
                self.send_response(resp_code, msg_buf)
                    .await
                    .inspect_err(|_| {
                        writeln!(self.cw, "SPDM_LIB: Failed to send response").unwrap();
                    })?;
            }
            Err((rsp, command_error)) => {
                if rsp {
                    self.send_response(ReqRespCode::Error, msg_buf)
                        .await
                        .inspect_err(|_| {
                            writeln!(self.cw, "SPDM_LIB: Failed to send error response").unwrap();
                        })?;
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

        writeln!(
            self.cw,
            "SPDM_LIB: Decoded request. Hdr_version {:?} req_resp_code {:?}",
            req_msg_header.version(),
            req_msg_header.req_resp_code()
        )
        .unwrap();

        let req_code = req_msg_header
            .req_resp_code()
            .map_err(|_| (false, CommandError::UnsupportedRequest))?;
        let resp_code = req_code
            .response_code()
            .map_err(|_| (false, CommandError::UnsupportedRequest))?;

        match req_code {
            ReqRespCode::GetVersion => {
                writeln!(self.cw, "SPDM_LIB: Handling Version").unwrap();
                self.handle_version(req_msg_header, req).await?
            }
            _ => {
                writeln!(self.cw, "SPDM_LIB: Unsupported request").unwrap();
                Err((false, CommandError::UnsupportedRequest))?
            }
        }
        Ok(resp_code)
    }

    async fn send_response(
        &mut self,
        resp_code: ReqRespCode,
        resp: &mut MessageBuf<'a>,
    ) -> SpdmResult<()> {
        let spdm_version = self.state.version_number();
        let spdm_resp_hdr = SpdmMsgHdr::new(spdm_version, resp_code);
        spdm_resp_hdr.encode(resp)?;

        writeln!(
            self.cw,
            "SPDM_LIB: SpdmCtx Sending response of len {} {:?}",
            resp.data_len(),
            resp.total_message(),
        )
        .unwrap();
        self.transport.send_response(resp).await.map_err(|e| {
            writeln!(self.cw, "SPDM_LIB: Failed to send response").unwrap();
            SpdmError::Transport(e)
        })
    }

    async fn handle_version(
        &mut self,
        spdm_hdr: SpdmMsgHdr,
        req_payload: &mut MessageBuf<'a>,
    ) -> CommandResult<()> {
        match spdm_hdr.version() {
            Ok(SpdmVersion::V10) => {}
            _ => {
                writeln!(self.cw, "SPDM_LIB: Version Error").unwrap();
                self.generate_error_response(req_payload, ErrorCode::VersionMismatch, 0, None)?;
            }
        }

        self.state.reset();
        let rsp_buf = req_payload;
        self.generate_version_response(rsp_buf)?;
        writeln!(
            self.cw,
            "Get Version Success. Generated response of len {}",
            rsp_buf.msg_len()
        )
        .unwrap();

        self.state
            .set_connection_state(ConnectionState::AfterVersion);
        Ok(())
    }

    fn prepare_response_buffer(&self, rsp_buf: &mut MessageBuf) -> CommandResult<()> {
        rsp_buf.reset();
        rsp_buf
            .reserve(self.transport.header_size() + core::mem::size_of::<SpdmMsgHdr>())
            .map_err(|_| (false, CommandError::BufferTooSmall))?;
        Ok(())
    }

    fn generate_version_response(&mut self, rsp_buf: &mut MessageBuf) -> CommandResult<()> {
        self.prepare_response_buffer(rsp_buf)?;
        version_rsp::fill_version_response(rsp_buf, self.supported_versions)
    }

    fn generate_error_response(
        &self,
        msg_buf: &mut MessageBuf,
        error_code: ErrorCode,
        error_data: u8,
        extended_data: Option<&[u8]>,
    ) -> CommandResult<()> {
        self.prepare_response_buffer(msg_buf)?;
        fill_error_response(msg_buf, error_code, error_data, extended_data)
    }
}
