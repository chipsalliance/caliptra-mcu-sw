// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::codec::{Codec, MessageBuf};
use crate::protocol::StandardsBodyId;
use crate::vdm_handler::iana::ocp::caliptra_vdm::commands::{
    device_capabilities, device_id, device_info, export_attested_csr, firmware_version,
};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::*;
use crate::vdm_handler::{VdmError, VdmHandler, VdmRegistryMatcher, VdmResponder, VdmResult};
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_common_commands::CaliptraCmdHandler;
use core::mem::size_of;

pub(crate) mod commands;
pub mod protocol;

pub struct CaliptraVdmHandler<'a> {
    pub(crate) handler: &'a dyn CaliptraCmdHandler,
}

impl<'a> CaliptraVdmHandler<'a> {
    #[allow(dead_code)]
    pub fn new(handler: &'a dyn CaliptraCmdHandler) -> Self {
        Self { handler }
    }
}

impl VdmRegistryMatcher for CaliptraVdmHandler<'_> {
    fn match_id(
        &self,
        standard_id: StandardsBodyId,
        vendor_id: &[u8],
        _secure_session: bool,
    ) -> bool {
        standard_id == StandardsBodyId::Iana && vendor_id == OCP_VENDOR_ID.to_le_bytes()
    }
}

#[async_trait]
impl VdmResponder for CaliptraVdmHandler<'_> {
    async fn handle_request(
        &mut self,
        req_buf: &mut MessageBuf<'_>,
        rsp_buf: &mut MessageBuf<'_>,
        large_rsp_buf: &mut [u8],
    ) -> VdmResult<usize> {
        // Decode command header [command_version, command_code]
        let hdr = CaliptraVdmMsgHeader::decode(req_buf).map_err(VdmError::Codec)?;

        if hdr.command_version != CALIPTRA_VDM_COMMAND_VERSION {
            return Err(VdmError::UnsupportedRequest);
        }

        let command = CaliptraVdmCommand::try_from(hdr.command_code)?;

        // Reserve space for response header
        let rsp_hdr_len = size_of::<CaliptraVdmMsgHeader>();
        rsp_buf.reserve(rsp_hdr_len).map_err(VdmError::Codec)?;

        let result = match command {
            CaliptraVdmCommand::FirmwareVersion => {
                firmware_version::handle_firmware_version(self.handler, req_buf, rsp_buf).await?
            }
            CaliptraVdmCommand::DeviceCapabilities => {
                device_capabilities::handle_device_capabilities(self.handler, req_buf, rsp_buf)
                    .await?
            }
            CaliptraVdmCommand::DeviceId => {
                device_id::handle_device_id(self.handler, req_buf, rsp_buf).await?
            }
            CaliptraVdmCommand::DeviceInfo => {
                device_info::handle_device_info(self.handler, req_buf, rsp_buf).await?
            }
            CaliptraVdmCommand::ExportAttestedCsr => {
                export_attested_csr::handle_export_attested_csr(
                    self.handler,
                    req_buf,
                    rsp_buf,
                    large_rsp_buf,
                )
                .await?
            }
            _ => CaliptraVdmCmdResult::ErrorResponse(CaliptraCompletionCode::UnsupportedOperation),
        };

        let len = match result {
            CaliptraVdmCmdResult::Response(payload_len) => {
                let rsp_hdr = CaliptraVdmMsgHeader {
                    command_version: CALIPTRA_VDM_COMMAND_VERSION,
                    command_code: command.response_code(),
                };
                rsp_buf.push_data(payload_len).map_err(VdmError::Codec)?;
                let hdr_len = rsp_hdr.encode(rsp_buf).map_err(VdmError::Codec)?;
                payload_len + hdr_len
            }
            CaliptraVdmCmdResult::ErrorResponse(error) => {
                generate_error_response(command, error, rsp_buf)?
            }
        };

        Ok(len)
    }
}

impl VdmHandler for CaliptraVdmHandler<'_> {}

/// Generate a CaliptraVdm error response, following the TDISP generate_error_response pattern.
/// Resets the payload region and encodes the error response (header + error code).
fn generate_error_response(
    command: CaliptraVdmCommand,
    error: CaliptraCompletionCode,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<usize> {
    rsp_buf.reset_payload();

    let mut len = (error as u8).encode(rsp_buf).map_err(VdmError::Codec)?;
    rsp_buf.push_data(len).map_err(VdmError::Codec)?;

    let rsp_hdr = CaliptraVdmMsgHeader {
        command_version: CALIPTRA_VDM_COMMAND_VERSION,
        command_code: command.response_code(),
    };
    len += rsp_hdr.encode(rsp_buf).map_err(VdmError::Codec)?;

    Ok(len)
}
