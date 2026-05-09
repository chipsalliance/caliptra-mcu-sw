// Licensed under the Apache-2.0 license

use crate::error::VdmLibError;
use crate::transport::MctpVdmTransport;
use core::convert::TryFrom;
use external_cmds_common::{
    DeviceCapabilities, DeviceId, DeviceInfo, FirmwareVersion, Uid, UnifiedCommandHandler,
    MAX_UID_LEN,
};
use mctp_vdm_common::codec::VdmCodec;
use mctp_vdm_common::message::{
    DeviceCapabilitiesResponse, DeviceIdResponse, DeviceInfoRequest, DeviceInfoResponse,
    FirmwareVersionRequest, FirmwareVersionResponse, DEVICE_CAPS_SIZE,
};
use mctp_vdm_common::protocol::{
    VdmCommand, VdmCompletionCode, VdmFailureResponse, VdmMsgHeader, VDM_MSG_HEADER_LEN,
};
use mctp_vdm_common::util::mctp_transport::{
    construct_mctp_vdm_msg, extract_vdm_msg, VDM_MSG_OFFSET,
};
use zerocopy::IntoBytes;

/// Command interface for handling VDM commands.
pub struct CmdInterface<'a> {
    transport: &'a mut MctpVdmTransport,
    unified_handler: &'a dyn UnifiedCommandHandler,
}

impl<'a> CmdInterface<'a> {
    /// Create a new command interface.
    pub fn new(
        transport: &'a mut MctpVdmTransport,
        unified_handler: &'a dyn UnifiedCommandHandler,
    ) -> Self {
        Self {
            transport,
            unified_handler,
        }
    }

    /// Handle a responder message (receive request, process, send response).
    pub async fn handle_responder_msg(&mut self, msg_buf: &mut [u8]) -> Result<(), VdmLibError> {
        // Receive a request from the transport.
        let req_len = self
            .transport
            .receive_request(msg_buf)
            .await
            .map_err(|_| VdmLibError::TransportError)?;

        // Process the request and prepare the response.
        let resp_len = self.process_request(msg_buf, req_len).await?;

        // Send the response.
        self.transport
            .send_response(&msg_buf[..resp_len])
            .await
            .map_err(|_| VdmLibError::TransportError)?;

        Ok(())
    }

    /// Process a VDM request and generate a response.
    async fn process_request(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<usize, VdmLibError> {
        if req_len < VDM_MSG_OFFSET {
            return self.send_error_response(msg_buf, 0, VdmCompletionCode::InvalidLength);
        }

        // Extract the VDM message from the MCTP payload, using only the received length.
        let vdm_msg =
            extract_vdm_msg(&mut msg_buf[..req_len]).map_err(|_| VdmLibError::DecodingError)?;

        // Need at least the VDM header.
        if vdm_msg.len() < VDM_MSG_HEADER_LEN {
            return self.send_error_response(msg_buf, 0, VdmCompletionCode::InvalidLength);
        }

        // Decode the VDM header.
        let hdr = VdmMsgHeader::decode(vdm_msg).map_err(|_| VdmLibError::DecodingError)?;

        // Validate the header.
        if !hdr.is_vendor_id_valid() {
            return self.send_error_response(
                msg_buf,
                hdr.command_code,
                VdmCompletionCode::InvalidData,
            );
        }

        if !hdr.is_request() {
            return self.send_error_response(
                msg_buf,
                hdr.command_code,
                VdmCompletionCode::InvalidData,
            );
        }

        // Parse the command code.
        let command = match VdmCommand::try_from(hdr.command_code) {
            Ok(cmd) => cmd,
            Err(_) => {
                return self.send_error_response(
                    msg_buf,
                    hdr.command_code,
                    VdmCompletionCode::UnsupportedCommand,
                );
            }
        };

        // Dispatch to the appropriate handler.
        let vdm_req_len = req_len - VDM_MSG_OFFSET;
        match command {
            VdmCommand::FirmwareVersion => self.handle_firmware_version(msg_buf, vdm_req_len).await,
            VdmCommand::DeviceCapabilities => {
                self.handle_device_capabilities(msg_buf, vdm_req_len).await
            }
            VdmCommand::DeviceId => self.handle_device_id(msg_buf, vdm_req_len).await,
            VdmCommand::DeviceInfo => self.handle_device_info(msg_buf, vdm_req_len).await,
            _ => self.send_error_response(
                msg_buf,
                hdr.command_code,
                VdmCompletionCode::UnsupportedCommand,
            ),
        }
    }

    /// Handle Firmware Version command.
    async fn handle_firmware_version(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<usize, VdmLibError> {
        // Extract VDM message portion.
        let vdm_msg = extract_vdm_msg(msg_buf).map_err(|_| VdmLibError::DecodingError)?;

        // Decode the request.
        let req = FirmwareVersionRequest::decode(&vdm_msg[..req_len])
            .map_err(|_| VdmLibError::DecodingError)?;

        // Get the firmware version using the unified handler.
        let mut version = FirmwareVersion::default();
        let area_index = req.area_index;
        let result = self
            .unified_handler
            .get_firmware_version(area_index, &mut version)
            .await;

        // Build the response.
        let (completion_code, ver_bytes) = match result {
            Ok(()) => (VdmCompletionCode::Success, &version.ver_str[..version.len]),
            Err(_) => (VdmCompletionCode::InvalidData, &[][..]),
        };

        let resp = FirmwareVersionResponse::new(completion_code as u32, ver_bytes);

        // Encode the response into the MCTP payload.
        self.encode_response(msg_buf, &resp)
    }

    /// Handle Device Capabilities command.
    async fn handle_device_capabilities(
        &self,
        msg_buf: &mut [u8],
        _req_len: usize,
    ) -> Result<usize, VdmLibError> {
        // Get the device capabilities using the unified handler.
        let mut caps = DeviceCapabilities::default();
        let result = self
            .unified_handler
            .get_device_capabilities(&mut caps)
            .await;

        // Build the response.
        let caps_bytes = match result {
            Ok(()) => {
                let mut c = [0u8; DEVICE_CAPS_SIZE];
                let caps_slice = caps.as_bytes();
                let len = caps_slice.len().min(DEVICE_CAPS_SIZE);
                c[..len].copy_from_slice(&caps_slice[..len]);
                c
            }
            Err(_) => [0u8; DEVICE_CAPS_SIZE],
        };

        let completion_code = match result {
            Ok(()) => VdmCompletionCode::Success,
            Err(_) => VdmCompletionCode::GeneralError,
        };

        let resp = DeviceCapabilitiesResponse::new(completion_code as u32, &caps_bytes);

        // Encode the response into the MCTP payload.
        self.encode_response(msg_buf, &resp)
    }

    /// Handle Device ID command.
    async fn handle_device_id(
        &self,
        msg_buf: &mut [u8],
        _req_len: usize,
    ) -> Result<usize, VdmLibError> {
        // Get the device ID using the unified handler.
        let mut device_id = DeviceId::default();
        let result = self.unified_handler.get_device_id(&mut device_id).await;

        // Build the response.
        let resp = match result {
            Ok(()) => DeviceIdResponse::new(
                VdmCompletionCode::Success as u32,
                device_id.vendor_id,
                device_id.device_id,
                device_id.subsystem_vendor_id,
                device_id.subsystem_id,
            ),
            Err(_) => DeviceIdResponse::new(VdmCompletionCode::GeneralError as u32, 0, 0, 0, 0),
        };

        // Encode the response into the MCTP payload.
        self.encode_response(msg_buf, &resp)
    }

    /// Handle Device Info command.
    async fn handle_device_info(
        &self,
        msg_buf: &mut [u8],
        req_len: usize,
    ) -> Result<usize, VdmLibError> {
        // Extract VDM message portion.
        let vdm_msg = extract_vdm_msg(msg_buf).map_err(|_| VdmLibError::DecodingError)?;

        // Decode the request.
        let req = DeviceInfoRequest::decode(&vdm_msg[..req_len])
            .map_err(|_| VdmLibError::DecodingError)?;

        // Get the device info using the unified handler.
        let mut info = DeviceInfo::Uid(Uid::default());
        let info_index = req.info_index;
        let result = self
            .unified_handler
            .get_device_info(info_index, &mut info)
            .await;

        // Build the response.
        let (completion_code, data) = match result {
            Ok(()) => {
                let DeviceInfo::Uid(uid) = &info;
                let len = uid.len.min(MAX_UID_LEN);
                (
                    VdmCompletionCode::Success,
                    uid.unique_chip_id[..len].to_vec(),
                )
            }
            Err(_) => (VdmCompletionCode::InvalidData, alloc::vec![]),
        };

        let resp = DeviceInfoResponse::new(completion_code as u32, &data);

        // Encode the response into the MCTP payload.
        self.encode_device_info_response(msg_buf, &resp)
    }

    /// Send an error response.
    fn send_error_response(
        &self,
        msg_buf: &mut [u8],
        command_code: u8,
        completion_code: VdmCompletionCode,
    ) -> Result<usize, VdmLibError> {
        let resp = VdmFailureResponse::new(command_code, completion_code);
        self.encode_response(msg_buf, &resp)
    }

    /// Encode a response into the MCTP payload buffer.
    fn encode_response<T: VdmCodec>(
        &self,
        msg_buf: &mut [u8],
        resp: &T,
    ) -> Result<usize, VdmLibError> {
        // Construct MCTP header and get VDM message slice.
        let vdm_msg = construct_mctp_vdm_msg(msg_buf).map_err(|_| VdmLibError::EncodingError)?;

        // Encode the response.
        let resp_len = resp
            .encode(vdm_msg)
            .map_err(|_| VdmLibError::EncodingError)?;

        // Return total MCTP payload length (1 byte MCTP header + VDM response).
        Ok(VDM_MSG_OFFSET + resp_len)
    }

    /// Encode a DeviceInfoResponse (variable length) into the MCTP payload buffer.
    fn encode_device_info_response(
        &self,
        msg_buf: &mut [u8],
        resp: &DeviceInfoResponse,
    ) -> Result<usize, VdmLibError> {
        // Construct MCTP header and get VDM message slice.
        let vdm_msg = construct_mctp_vdm_msg(msg_buf).map_err(|_| VdmLibError::EncodingError)?;

        // Encode the response.
        let resp_len = resp
            .encode(vdm_msg)
            .map_err(|_| VdmLibError::EncodingError)?;

        // Return total MCTP payload length (1 byte MCTP header + VDM response).
        Ok(VDM_MSG_OFFSET + resp_len)
    }
}
