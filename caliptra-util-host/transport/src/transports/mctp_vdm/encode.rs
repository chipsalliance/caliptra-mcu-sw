// Licensed under the Apache-2.0 license

//! VDM command encoder/decoder
//!
//! This module provides encoding of internal `caliptra-util-host-command-types`
//! requests into MCTP VDM wire-format packets (using `mctp-vdm-common` message
//! types) and decoding of VDM responses back into internal response types.
//!
//! Currently supported commands:
//! - FirmwareVersion  (0x01)
//! - DeviceCapabilities (0x02)
//! - GetDebugLog (0x03)
//! - ClearDebugLog (0x04)

use super::transport::MctpVdmError;
use crate::TransportError;
use caliptra_mcu_core_util_host_command_types::*;
use caliptra_mcu_mctp_vdm_common::codec::VdmCodec;
use caliptra_mcu_mctp_vdm_common::message::{
    ClearDebugLogRequest, ClearDebugLogResponse, DeviceCapabilitiesRequest,
    DeviceCapabilitiesResponse, FirmwareVersionRequest, FirmwareVersionResponse,
    MAX_FW_VERSION_LEN,
};
use caliptra_mcu_mctp_vdm_common::protocol::{VdmCompletionCode, VdmMsgHeader, VDM_MSG_HEADER_LEN};

/// Maximum buffer for encoding a VDM request.
const MAX_VDM_REQ_BUF: usize = 128;

/// Maximum buffer for a VDM response from the driver.
const MAX_VDM_RESP_BUF: usize = 256;

// ---------------------------------------------------------------------------
// Helper: send a VDM request and get raw response bytes (copied into buf)
// ---------------------------------------------------------------------------

/// Encode a VDM message, send it via the driver, copy the response into `buf`,
/// and return the number of response bytes.
fn send_vdm<R: VdmCodec>(
    request: &R,
    driver: &mut dyn super::transport::MctpVdmDriver,
    buf: &mut [u8; MAX_VDM_RESP_BUF],
) -> Result<usize, TransportError> {
    let mut req_buf = [0u8; MAX_VDM_REQ_BUF];
    let req_len = request
        .encode(&mut req_buf)
        .map_err(|_| TransportError::InvalidMessage)?;

    let resp = driver
        .send_request(&req_buf[..req_len])
        .map_err(TransportError::from)?;

    let copy_len = resp.len().min(MAX_VDM_RESP_BUF);
    buf[..copy_len].copy_from_slice(&resp[..copy_len]);
    Ok(copy_len)
}

/// Validate the VDM response header: check it is a response and that the
/// completion code is `Success`. Returns the completion code on error.
fn validate_response_header(resp: &[u8]) -> Result<(), TransportError> {
    if resp.len() < VDM_MSG_HEADER_LEN + 4 {
        return Err(TransportError::InvalidMessage);
    }
    let hdr = VdmMsgHeader::decode(resp).map_err(|_| TransportError::InvalidMessage)?;
    if !hdr.is_response() {
        return Err(TransportError::InvalidMessage);
    }
    let cc_bytes: [u8; 4] = resp[VDM_MSG_HEADER_LEN..VDM_MSG_HEADER_LEN + 4]
        .try_into()
        .map_err(|_| TransportError::InvalidMessage)?;
    let cc = u32::from_le_bytes(cc_bytes);
    let code = VdmCompletionCode::try_from(cc).map_err(|_| TransportError::InvalidMessage)?;
    if code != VdmCompletionCode::Success {
        return Err(TransportError::from(MctpVdmError::DeviceError(cc)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FirmwareVersion (command_id = 1 / CaliptraCommandId::GetFirmwareVersion)
// ---------------------------------------------------------------------------

pub fn handle_firmware_version(
    payload: &[u8],
    driver: &mut dyn super::transport::MctpVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    // Parse internal request (may be empty → default to index 0)
    let area_index = if payload.len() >= core::mem::size_of::<GetFirmwareVersionRequest>() {
        let req = GetFirmwareVersionRequest::from_bytes(payload)
            .map_err(|_| TransportError::InvalidMessage)?;
        req.index
    } else {
        0
    };

    // Build VDM request
    let vdm_req = FirmwareVersionRequest::new(area_index);
    let mut resp_buf = [0u8; MAX_VDM_RESP_BUF];
    let resp_len = send_vdm(&vdm_req, driver, &mut resp_buf)?;
    let resp_bytes = &resp_buf[..resp_len];
    validate_response_header(resp_bytes)?;

    // Decode VDM response
    let vdm_resp =
        FirmwareVersionResponse::decode(resp_bytes).map_err(|_| TransportError::InvalidMessage)?;

    // Convert to internal response
    let version_data = &vdm_resp.version;
    let mut version = [0u32; 4];
    let actual_len = version_data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(MAX_FW_VERSION_LEN);
    let version_str = core::str::from_utf8(&version_data[..actual_len])
        .unwrap_or("")
        .trim_end_matches('\0');
    if let Some((version_part, _)) = version_str.split_once(' ') {
        for (i, part) in version_part.split('.').take(4).enumerate() {
            if let Ok(num) = part.parse::<u32>() {
                version[i] = num;
            }
        }
    } else {
        for (i, part) in version_str.split('.').take(4).enumerate() {
            if let Ok(num) = part.parse::<u32>() {
                version[i] = num;
            }
        }
    }

    let mut commit_id = [0u8; 20];
    if let Some((_, commit_part)) = version_str.split_once(' ') {
        let cb = commit_part.as_bytes();
        let len = cb.len().min(20);
        commit_id[..len].copy_from_slice(&cb[..len]);
    }

    let internal_resp = GetFirmwareVersionResponse {
        common: CommonResponse {
            fips_status: vdm_resp.completion_code,
        },
        version,
        commit_id,
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// DeviceCapabilities (command_id = 2 / CaliptraCommandId::GetDeviceCapabilities)
// ---------------------------------------------------------------------------

pub fn handle_device_capabilities(
    _payload: &[u8],
    driver: &mut dyn super::transport::MctpVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let vdm_req = DeviceCapabilitiesRequest::new();
    let mut resp_buf = [0u8; MAX_VDM_RESP_BUF];
    let resp_len = send_vdm(&vdm_req, driver, &mut resp_buf)?;
    let resp_bytes = &resp_buf[..resp_len];
    validate_response_header(resp_bytes)?;

    let vdm_resp = DeviceCapabilitiesResponse::decode(resp_bytes)
        .map_err(|_| TransportError::InvalidMessage)?;

    let caps = vdm_resp.caps;
    let internal_resp = GetDeviceCapabilitiesResponse {
        common: CommonResponse {
            fips_status: vdm_resp.completion_code,
        },
        capabilities: u32::from_le_bytes([caps[0], caps[1], caps[2], caps[3]]),
        max_cert_size: u32::from_le_bytes([caps[4], caps[5], caps[6], caps[7]]),
        max_csr_size: u32::from_le_bytes([caps[8], caps[9], caps[10], caps[11]]),
        device_lifecycle: u32::from_le_bytes([caps[12], caps[13], caps[14], caps[15]]),
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// GetDebugLog (command_id = 0x7005 / CaliptraCommandId::DebugGetLog)
// ---------------------------------------------------------------------------

pub fn handle_get_debug_log(
    _payload: &[u8],
    driver: &mut dyn super::transport::MctpVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    use alloc::vec;
    use caliptra_mcu_core_util_host_command_types::device_log::{
        DebugGetLogResponse, MAX_DEBUG_LOG_DATA_SIZE,
    };
    use caliptra_mcu_mctp_vdm_common::message::{
        GetDebugLogRequest, GetDebugLogResponse, MAX_LOG_DATA_SIZE,
    };

    let vdm_req = GetDebugLogRequest::new();
    let mut req_buf = [0u8; MAX_VDM_REQ_BUF];
    let req_len = vdm_req
        .encode(&mut req_buf)
        .map_err(|_| TransportError::InvalidMessage)?;

    let resp = driver
        .send_request(&req_buf[..req_len])
        .map_err(TransportError::from)?;

    let resp_buf_size = core::mem::size_of::<GetDebugLogResponse>()
        .max(VDM_MSG_HEADER_LEN + 16 + MAX_LOG_DATA_SIZE);
    let mut resp_buf = vec![0u8; resp_buf_size];
    let copy_len = resp.len().min(resp_buf.len());
    resp_buf[..copy_len].copy_from_slice(&resp[..copy_len]);
    let resp_bytes = &resp_buf[..copy_len];

    validate_response_header(resp_bytes)?;

    let vdm_resp =
        GetDebugLogResponse::decode(resp_bytes).map_err(|_| TransportError::InvalidMessage)?;

    let log = vdm_resp.data();
    let data_len = log.len().min(MAX_DEBUG_LOG_DATA_SIZE);
    let mut data = [0u8; MAX_DEBUG_LOG_DATA_SIZE];
    data[..data_len].copy_from_slice(&log[..data_len]);

    let internal_resp = DebugGetLogResponse {
        common: CommonResponse {
            fips_status: vdm_resp.header.completion_code,
        },
        more_data: if vdm_resp.more_data() { 1 } else { 0 },
        data_len: data_len as u32,
        data,
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// ClearDebugLog (OCP Caliptra VDM command 0x04)
// ---------------------------------------------------------------------------

pub fn handle_clear_debug_log(
    _payload: &[u8],
    driver: &mut dyn super::transport::MctpVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    use caliptra_mcu_core_util_host_command_types::device_log::DebugClearLogResponse;

    let vdm_req = ClearDebugLogRequest::new();
    let mut resp_buf = [0u8; MAX_VDM_RESP_BUF];
    let resp_len = send_vdm(&vdm_req, driver, &mut resp_buf)?;
    let resp_bytes = &resp_buf[..resp_len];
    validate_response_header(resp_bytes)?;

    let vdm_resp =
        ClearDebugLogResponse::decode(resp_bytes).map_err(|_| TransportError::InvalidMessage)?;

    let internal_resp = DebugClearLogResponse {
        common: CommonResponse {
            fips_status: vdm_resp.completion_code,
        },
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_mcu_mctp_vdm_common::codec::VdmCodec;
    use caliptra_mcu_mctp_vdm_common::protocol::CALIPTRA_IANA_ENTERPRISE_ID_BYTES;

    // Verify that request encoding produces valid VDM wire bytes
    #[test]
    fn test_encode_firmware_version_request() {
        let req = FirmwareVersionRequest::new(1);
        let mut buf = [0u8; 64];
        let len = req.encode(&mut buf).unwrap();
        assert_eq!(len, VDM_MSG_HEADER_LEN + 4);
        assert_eq!(&buf[..4], &CALIPTRA_IANA_ENTERPRISE_ID_BYTES);
    }

    #[test]
    fn test_encode_device_capabilities_request() {
        let req = DeviceCapabilitiesRequest::new();
        let mut buf = [0u8; 64];
        let len = req.encode(&mut buf).unwrap();
        assert_eq!(len, VDM_MSG_HEADER_LEN);
    }
}
