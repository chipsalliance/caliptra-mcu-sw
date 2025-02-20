// Licensed under the Apache-2.0 license

use crate::error::*;
use crate::error_rsp::ErrorResponse;
use crate::error_rsp::{CommandError, ErrorCode};
use crate::message_buf::{Codec, MessageBuf};
use crate::protocol::SpdmMsgHdr;
use crate::req_resp_codes::{CommandResult, ReqRespCode};
use crate::state::{ConnectionState, State};
use crate::transport::MctpTransport;
use crate::version_rsp::{SpdmVersion, VersionNumberEntry, VersionRespCommon};
use zerocopy::{FromBytes, IntoBytes};

// use libsyscall_caliptra::mctp::{driver_num, Mctp};
use crate::error::*;
use core::fmt::Write;
use libtock_console::{Console, ConsoleWriter};
use libtock_platform::Syscalls;

pub const MAX_SPDM_MSG_SIZE: usize = 1024;

pub const MAX_NUM_SUPPORTED_SPDM_VERSIONS: usize = 2;
pub const MAX_SUPORTED_VERSION: SpdmVersion = SpdmVersion::V13;

pub struct SpdmContext<'a, S: Syscalls> {
    supported_versions: &'a [SpdmVersion],
    transport: &'a mut MctpTransport<S>,
    secure_transport: &'a mut MctpTransport<S>,
    state: State,
    cw: &'a mut ConsoleWriter<S>,
}

impl<'a, S: Syscalls> SpdmContext<'a, S> {
    pub fn new(
        supported_versions: &'a [SpdmVersion],
        spdm_transport: &'a mut MctpTransport<S>,
        secure_spdm_transport: &'a mut MctpTransport<S>,
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
            secure_transport: secure_spdm_transport,
            state: State::new(),
            cw,
        })
    }

    pub async fn process_message(&mut self, msg_buf: &mut MessageBuf<'a>) -> SpdmResult<()> {
        writeln!(self.cw, "SPDM_LIB: Start processing the message").unwrap();
        // let mut buf = &raw_buf[..];

        // let mut msg_buf = MessageBuf::new(raw_buf, 0).ok_or(SpdmError::BufferTooSmall)?;

        self.transport.receive_request(msg_buf).await.map_err(|e| {
            writeln!(self.cw, "SPDM_LIB: Failed to receive request").unwrap();
            e
        })?;
        writeln!(self.cw, "SPDM_LIB: Received request").unwrap();

        // let mut req_buf = MessageBuf::new(&mut raw_buf[transport_hdr_size..], msg_len)
        //     .ok_or(SpdmError::BufferTooSmall)?;

        // Process message
        self.handle_request(msg_buf).await.map_err(|e| {
            writeln!(self.cw, "SPDM_LIB: Failed to handle request").unwrap();
            e
        })?;

        Ok(())
    }

    async fn handle_request(&mut self, buf: &mut MessageBuf<'a>) -> SpdmResult<()> {
        writeln!(
            self.cw,
            "SPDM_LIB: Handling request buffer {:X?}",
            buf.data(2)
        )
        .unwrap();
        let mut req = buf;

        let req_msg_header: SpdmMsgHdr = SpdmMsgHdr::decode(req)?;

        writeln!(
            self.cw,
            "SPDM_LIB: Decoded request. Hdr_version {:?} req_resp_code {:?}",
            req_msg_header.version(),
            req_msg_header.req_resp_code()
        )
        .unwrap();

        let req_code = req_msg_header.req_resp_code();
        let mut resp_code = req_code
            .response_code()
            .ok_or(SpdmError::UnsupportedRequest)?;

        let result = match req_code {
            ReqRespCode::GetVersion => {
                writeln!(self.cw, "SPDM_LIB: Handling Version").unwrap();
                self.handle_version(req_msg_header, &mut req).await
            }
            _ => {
                writeln!(self.cw, "SPDM_LIB: Unsupported request").unwrap();
                return Err(SpdmError::Command(CommandError::UnsupportedRequest));
            }
        };

        let mut send_resp = false;
        let result = match result {
            CommandResult::Success => {
                writeln!(self.cw, "SPDM_LIB: Success").unwrap();
                send_resp = true;
                None
            }
            CommandResult::ErrorResponse(err) => {
                writeln!(self.cw, "SPDM_LIB: ErrorNoResponse").unwrap();
                send_resp = true;
                resp_code = ReqRespCode::Error;
                Some(err)
            }
            CommandResult::ErrorNoResponse(err) => {
                writeln!(self.cw, "SPDM_LIB: Error").unwrap();
                Some(err)
            }
        };

        if send_resp {
            writeln!(self.cw, "SPDM_LIB: Sending response").unwrap();
            self.send_response(resp_code, &mut req).await.map_err(|e| {
                writeln!(self.cw, "SPDM_LIB: Failed to send response").unwrap();
                e
            })?;
        }

        match result {
            Some(err) => Err(SpdmError::Command(err)),
            None => Ok(()),
        }
    }

    async fn send_response(
        &mut self,
        resp_code: ReqRespCode,
        resp: &mut MessageBuf<'a>,
    ) -> SpdmResult<()> {
        let spdm_version = self.state.version_number();
        let spdm_resp_hdr = SpdmMsgHdr::new(spdm_version, resp_code);
        let mut len = match spdm_resp_hdr.encode(resp) {
            Ok(len) => len,
            Err(_) => return Err(SpdmError::BufferTooSmall),
        };

        let len = resp.len();

        writeln!(
            self.cw,
            "SPDM_LIB: SpdmCtx Sending response of len {} {:?}",
            len,
            resp.data(len)
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
    ) -> CommandResult {
        if spdm_hdr.version() != SpdmVersion::V10 {
            return self.generate_error_response(ErrorCode::VersionMismatch, 0, None, req_payload);
        }

        self.state.reset();
        let rsp_buf = req_payload;
        // rsp_buf.reset();
        let result = self.generate_version_response(rsp_buf);
        match result {
            CommandResult::Success => {
                writeln!(
                    self.cw,
                    "Get Version Success. Generated response of len {}",
                    rsp_buf.len()
                )
                .unwrap();
                self.state
                    .set_connection_state(ConnectionState::AfterVersion);
                result
            }
            _ => {
                writeln!(self.cw, "Get Version Error").unwrap();
                result
            }
        }
    }

    pub fn generate_version_response(&mut self, rsp_buf: &mut MessageBuf) -> CommandResult {
        // Reset response buffer
        rsp_buf.reset();

        // Reserve space for the headers
        match rsp_buf.reserve(self.transport.header_size() + core::mem::size_of::<SpdmMsgHdr>()) {
            Ok(_) => {}
            Err(_) => return CommandResult::ErrorNoResponse(CommandError::BufferTooSmall),
        }

        writeln!(
            self.cw,
            "SPDM_LIB 1: Generating version response cur len {} data len {}",
            rsp_buf.len(),
            rsp_buf.data_len(),
        )
        .unwrap();

        // Compute the total payload length

        let entry_count = self.supported_versions.len() as u8;

        let total_payload_len = core::mem::size_of::<VersionRespCommon<[u8; 4]>>()
            + entry_count as usize * core::mem::size_of::<VersionNumberEntry<[u8; 2]>>();

        // Make space for payload
        // match rsp_buf.put_data(total_payload_len) {
        //     Ok(_) => {
        //         writeln!(
        //             self.cw,
        //             "SPDM_LIB 2: Making space for payload cur len {} data len {} {:?}",
        //             rsp_buf.len(),
        //             rsp_buf.data_len(),
        //             rsp_buf.total_data(),
        //         )
        //         .unwrap();
        //     }
        //     Err(_) => return CommandResult::ErrorNoResponse(CommandError::BufferTooSmall),
        // };

        // Encode
        let resp_common = VersionRespCommon::new(entry_count);
        match resp_common.encode(rsp_buf) {
            Ok(len) => len,
            Err(_) => return CommandResult::ErrorNoResponse(CommandError::BufferTooSmall),
        };

        writeln!(
            self.cw,
            "SPDM_LIB 3: Generating version response cur len {} data len {} {:?} entry count {}",
            rsp_buf.len(),
            rsp_buf.data_len(),
            rsp_buf.total_data(),
            resp_common.version_num_entry_count(),
        )
        .unwrap();

        // Construct response
        let payload_len =
            entry_count as usize * core::mem::size_of::<VersionNumberEntry<[u8; 2]>>();

        // Make space for payload
        match rsp_buf.put_data(payload_len) {
            Ok(_) => {
                writeln!(
                    self.cw,
                    "SPDM_LIB 3.1: Generating version response cur len {} data len {} {:?}",
                    rsp_buf.len(),
                    rsp_buf.data_len(),
                    rsp_buf.total_data(),
                )
                .unwrap();
            }
            Err(_) => return CommandResult::ErrorNoResponse(CommandError::BufferTooSmall),
        };

        // Get the data buffer for the payload and fill it
        let payload = match rsp_buf.data_mut(payload_len) {
            Ok(payload) => payload,
            Err(_) => return CommandResult::ErrorNoResponse(CommandError::BufferTooSmall),
        };

        for (i, &version) in self.supported_versions.iter().enumerate() {
            let entry = VersionNumberEntry::new(version);
            let entry_bytes = entry.as_bytes();
            let start = i * entry_bytes.len();
            let end = start + entry_bytes.len();
            payload[start..end].copy_from_slice(entry_bytes);
        }

        let final_len = rsp_buf.len();
        writeln!(
            self.cw,
            "SPDM_LIB 4: Generating version response cur len {} {:?}",
            final_len,
            rsp_buf.total_data()
        )
        .unwrap();

        CommandResult::Success
    }

    pub fn generate_error_response(
        &self,
        error_code: ErrorCode,
        error_data: u8,
        extended_data: Option<&[u8]>,
        msg_buf: &mut MessageBuf,
    ) -> CommandResult {
        msg_buf.reset();

        match msg_buf.reserve(self.transport.header_size() + core::mem::size_of::<SpdmMsgHdr>()) {
            Ok(_) => {}
            Err(_) => return CommandResult::ErrorNoResponse(CommandError::BufferTooSmall),
        }

        // SPDM response payload
        let error_payload =
            ErrorResponse::new(error_code.clone().into(), error_data, extended_data);
        if let Some(error_payload) = error_payload {
            error_payload.encode(msg_buf).ok();
            CommandResult::ErrorResponse(CommandError::ErrorCode(error_code))
        } else {
            CommandResult::ErrorNoResponse(CommandError::BufferTooSmall)
        }
    }
}
