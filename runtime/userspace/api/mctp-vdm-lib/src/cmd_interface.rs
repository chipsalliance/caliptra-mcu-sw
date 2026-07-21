// Licensed under the Apache-2.0 license

use crate::error::VdmLibError;
use crate::transport::MctpVdmTransport;
use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, CaliptraCompletionCode, DeviceCapabilities, FirmwareVersion, GetLogResult,
    LogType,
};
use caliptra_mcu_mctp_vdm_common::codec::VdmCodec;
use caliptra_mcu_mctp_vdm_common::message::{
    ClearDebugLogResponse, DeviceCapabilitiesResponse, FirmwareVersionRequest,
    FirmwareVersionResponse, GetDebugLogResponse, DEVICE_CAPS_SIZE, MAX_LOG_DATA_SIZE,
};
use caliptra_mcu_mctp_vdm_common::protocol::{
    VdmCommand, VdmCompletionCode, VdmFailureResponse, VdmMsgHeader, VDM_MSG_HEADER_LEN,
};
use caliptra_mcu_mctp_vdm_common::util::mctp_transport::{
    construct_mctp_vdm_msg, extract_vdm_msg, VDM_MSG_OFFSET,
};
use core::convert::TryFrom;
use zerocopy::IntoBytes;

/// Command interface for handling VDM commands.
pub struct CmdInterface<'a, H: CaliptraCmdHandler> {
    transport: &'a mut MctpVdmTransport,
    unified_handler: &'a H,
}

impl<'a, H: CaliptraCmdHandler> CmdInterface<'a, H> {
    /// Create a new command interface.
    pub fn new(transport: &'a mut MctpVdmTransport, unified_handler: &'a H) -> Self {
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
                VdmCompletionCode::InvalidParameter,
            );
        }

        if !hdr.is_request() || !hdr.reserved_is_zero() {
            return self.send_error_response(
                msg_buf,
                hdr.command_code,
                VdmCompletionCode::InvalidParameter,
            );
        }

        // Parse the command code.
        let command = match VdmCommand::try_from(hdr.command_code) {
            Ok(cmd) => cmd,
            Err(_) => {
                return self.send_error_response(
                    msg_buf,
                    hdr.command_code,
                    VdmCompletionCode::UnsupportedOperation,
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
            VdmCommand::GetDebugLog => self.handle_get_log(msg_buf, LogType::Debug).await,
            VdmCommand::ClearDebugLog => self.handle_clear_log(msg_buf, LogType::Debug).await,
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
            Err(_) => (VdmCompletionCode::InvalidParameter, &[][..]),
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

    /// Handle Get Debug Log command.
    ///
    /// Drains debug log entries into the response buffer. Sets the `more_data`
    /// flag in the response if at least one further entry remains.
    async fn handle_get_log(
        &self,
        msg_buf: &mut [u8],
        log_type: LogType,
    ) -> Result<usize, VdmLibError> {
        if log_type != LogType::Debug {
            return self.send_error_response(
                msg_buf,
                VdmCommand::GetDebugLog as u8,
                VdmCompletionCode::UnsupportedOperation,
            );
        }

        let mut data = [0u8; MAX_LOG_DATA_SIZE];
        let result = self
            .unified_handler
            .get_log(log_type as u32, &mut data)
            .await;

        match result {
            Ok(GetLogResult {
                bytes_written,
                more_data,
            }) => {
                let resp = GetDebugLogResponse::new(
                    VdmCompletionCode::Success as u32,
                    more_data,
                    &data[..bytes_written],
                );
                self.encode_get_debug_log_response(msg_buf, &resp)
            }
            Err(err) => {
                let cc = map_caliptra_to_vdm(err);
                self.send_error_response(msg_buf, VdmCommand::GetDebugLog as u8, cc)
            }
        }
    }

    /// Handle Clear Debug Log command.
    async fn handle_clear_log(
        &self,
        msg_buf: &mut [u8],
        log_type: LogType,
    ) -> Result<usize, VdmLibError> {
        if log_type != LogType::Debug {
            return self.send_error_response(
                msg_buf,
                VdmCommand::ClearDebugLog as u8,
                VdmCompletionCode::UnsupportedOperation,
            );
        }

        let result = self.unified_handler.clear_log(log_type as u32).await;

        match result {
            Ok(()) => {
                let resp = ClearDebugLogResponse::new(VdmCompletionCode::Success as u32);
                self.encode_response(msg_buf, &resp)
            }
            Err(err) => {
                let cc = map_caliptra_to_vdm(err);
                self.send_error_response(msg_buf, VdmCommand::ClearDebugLog as u8, cc)
            }
        }
    }

    /// Encode a GetDebugLogResponse (variable length) into the MCTP payload buffer.
    fn encode_get_debug_log_response(
        &self,
        msg_buf: &mut [u8],
        resp: &GetDebugLogResponse,
    ) -> Result<usize, VdmLibError> {
        let vdm_msg = construct_mctp_vdm_msg(msg_buf).map_err(|_| VdmLibError::EncodingError)?;
        let resp_len = resp
            .encode(vdm_msg)
            .map_err(|_| VdmLibError::EncodingError)?;
        Ok(VDM_MSG_OFFSET + resp_len)
    }
}

/// Map a `CaliptraCompletionCode` from the unified handler into the
/// MCTP VDM completion code space.
fn map_caliptra_to_vdm(err: CaliptraCompletionCode) -> VdmCompletionCode {
    match err {
        CaliptraCompletionCode::Success => VdmCompletionCode::Success,
        CaliptraCompletionCode::GeneralError => VdmCompletionCode::GeneralError,
        CaliptraCompletionCode::InvalidParameter => VdmCompletionCode::InvalidParameter,
        CaliptraCompletionCode::InvalidLength => VdmCompletionCode::InvalidLength,
        CaliptraCompletionCode::InvalidIdentifier => VdmCompletionCode::InvalidIdentifier,
        CaliptraCompletionCode::OperationFailed => VdmCompletionCode::OperationFailed,
        CaliptraCompletionCode::InsufficientResources => VdmCompletionCode::InsufficientResources,
        CaliptraCompletionCode::UnsupportedOperation => VdmCompletionCode::UnsupportedOperation,
        CaliptraCompletionCode::DeviceNotReady => VdmCompletionCode::DeviceNotReady,
        CaliptraCompletionCode::InvalidCommandVersion => VdmCompletionCode::InvalidCommandVersion,
        CaliptraCompletionCode::InvalidPayloadSize => VdmCompletionCode::InvalidPayloadSize,
        CaliptraCompletionCode::Timeout => VdmCompletionCode::Timeout,
        CaliptraCompletionCode::AccessDenied => VdmCompletionCode::AccessDenied,
        CaliptraCompletionCode::ResourceUnavailable => VdmCompletionCode::ResourceUnavailable,
        CaliptraCompletionCode::PolicyViolation => VdmCompletionCode::PolicyViolation,
        CaliptraCompletionCode::InvalidState => VdmCompletionCode::InvalidState,
        CaliptraCompletionCode::CaliptraMailboxBusy => VdmCompletionCode::CaliptraMailboxBusy,
        CaliptraCompletionCode::CaliptraBufferTooSmall => VdmCompletionCode::CaliptraBufferTooSmall,
    }
}
