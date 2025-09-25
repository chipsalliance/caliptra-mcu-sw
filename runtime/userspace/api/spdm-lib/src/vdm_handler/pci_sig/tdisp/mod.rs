// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::codec::{Codec, MessageBuf};
use crate::vdm_handler::pci_sig::tdisp::commands::error_rsp::generate_error_response;
use crate::vdm_handler::pci_sig::tdisp::commands::{
    device_interface_report, device_interface_state, lock_interface, start_interface_rsp,
    stop_interface_rsp, tdisp_capabilities, tdisp_version,
};
use crate::vdm_handler::pci_sig::tdisp::driver::TdispDriver;
use crate::vdm_handler::pci_sig::tdisp::protocol::*;
use crate::vdm_handler::pci_sig::tdisp::state::TdispState;
use crate::vdm_handler::{VdmError, VdmProtocolMatcher, VdmResponder, VdmResult};
use alloc::boxed::Box;
use async_trait::async_trait;

pub(crate) mod commands;
pub mod driver;
pub mod protocol;
pub(crate) mod state;

const TDISP_PROTOCOL_ID: u8 = 0x01;

pub const MAX_VENDOR_DEFINED_ERROR_DATA_SIZE: usize = 32;

pub enum TdispCmdResult {
    Response(usize),
    ErrorResponse(
        TdispError,
        u32,
        Option<[u8; MAX_VENDOR_DEFINED_ERROR_DATA_SIZE]>,
    ),
}

#[macro_export]
macro_rules! error_response {
    ($err:expr) => {
        Ok($crate::vdm_handler::pci_sig::tdisp::TdispCmdResult::ErrorResponse($err, 0, None))
    };
}

pub struct TdispResponder<'a> {
    supported_versions: &'a [TdispVersion],
    driver: &'a dyn TdispDriver,
    state: TdispState,
}

impl<'a> TdispResponder<'a> {
    pub fn new(
        supported_versions: &'a [TdispVersion],
        driver: &'a dyn TdispDriver,
    ) -> Option<Self> {
        if supported_versions.is_empty() {
            return None;
        }
        Some(Self {
            supported_versions,
            driver,
            state: TdispState::new(),
        })
    }
}

impl VdmProtocolMatcher for TdispResponder<'_> {
    fn match_protocol(&self, protocol_id: u8) -> bool {
        protocol_id == TDISP_PROTOCOL_ID
    }
}

#[async_trait]
impl VdmResponder for TdispResponder<'_> {
    async fn handle_request(
        &mut self,
        req_buf: &mut MessageBuf<'_>,
        rsp_buf: &mut MessageBuf<'_>,
    ) -> VdmResult<usize> {
        let req_hdr = TdispMessageHeader::decode(req_buf).map_err(VdmError::Codec)?;

        // Reserve space for TDISP response header
        let rsp_hdr_len = size_of::<TdispMessageHeader>();
        rsp_buf.reserve(rsp_hdr_len).map_err(VdmError::Codec)?;

        let version = TdispVersion::try_from(req_hdr.version)?;
        if version != TdispVersion::V10 {
            return generate_error_response(
                req_hdr.version,
                req_hdr.interface_id,
                TdispError::VersionMismatch,
                0,
                None,
                rsp_buf,
            );
        }

        let req_code = match TdispCommand::try_from(req_hdr.message_type) {
            Ok(cmd) => cmd,
            Err(_) => {
                return generate_error_response(
                    req_hdr.version,
                    req_hdr.interface_id,
                    TdispError::UnsupportedRequest,
                    req_hdr.message_type as u32,
                    None,
                    rsp_buf,
                );
            }
        };

        if req_buf.data_len() != req_code.payload_size() {
            return generate_error_response(
                req_hdr.version,
                req_hdr.interface_id,
                TdispError::InvalidRequest,
                0,
                None,
                rsp_buf,
            );
        }

        let result = match req_code {
            TdispCommand::GetTdispVersion => {
                tdisp_version::handle_get_tdisp_version(self, &req_hdr, rsp_buf)?
            }
            TdispCommand::GetTdispCapabilities => {
                tdisp_capabilities::handle_get_tdisp_capabilities(self, req_buf, rsp_buf).await?
            }
            TdispCommand::LockInterface => {
                lock_interface::handle_lock_interface(self, &req_hdr, req_buf, rsp_buf).await?
            }
            TdispCommand::GetDeviceInterfaceReport => {
                device_interface_report::handle_get_device_interface_report(
                    self, &req_hdr, req_buf, rsp_buf,
                )
                .await?
            }
            TdispCommand::GetDeviceInterfaceState => {
                device_interface_state::handle_get_device_interface_state(self, &req_hdr, rsp_buf)
                    .await?
            }
            TdispCommand::StartInterfaceRequest => {
                start_interface_rsp::handle_start_interface_request(self, &req_hdr, rsp_buf).await?
            }
            TdispCommand::StopInterfaceRequest => {
                stop_interface_rsp::handle_stop_interface_request(self, &req_hdr).await?
            }
            TdispCommand::BindP2PStreamRequest
            | TdispCommand::UnbindP2PStreamRequest
            | TdispCommand::SetMmioAttributeRequest
            | TdispCommand::VdmRequest => TdispCmdResult::ErrorResponse(
                TdispError::UnsupportedRequest,
                req_hdr.message_type as u32,
                None,
            ),
            _ => return Err(VdmError::InvalidVdmCommand),
        };
        let len = match result {
            TdispCmdResult::Response(len) => {
                let resp_code = req_code.response()?;
                let rsp_hdr =
                    TdispMessageHeader::new(req_hdr.version, resp_code, req_hdr.interface_id);
                let hdr_len = rsp_hdr.encode(rsp_buf).map_err(VdmError::Codec)?;
                len + hdr_len
            }
            TdispCmdResult::ErrorResponse(err_code, err_data, ext_data) => generate_error_response(
                req_hdr.version,
                req_hdr.interface_id,
                err_code,
                err_data,
                ext_data.as_ref().map(|data| data.as_ref()),
                rsp_buf,
            )?,
        };

        Ok(len)
    }
}
