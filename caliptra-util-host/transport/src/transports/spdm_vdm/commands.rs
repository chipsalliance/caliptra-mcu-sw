// Licensed under the Apache-2.0 license

//! VDM command encoder/decoder for SPDM VDM transport
//!
//! This module encodes internal `caliptra-util-host-command-types` requests
//! into Caliptra VDM wire-format payloads and decodes responses back into
//! internal response types.
//!
//! The Caliptra VDM wire format is:
//!   Request:  [version(1), command_code(1), payload...]
//!   Response: [version(1), command_code(1), completion_code(1), data...]
//!
//! Currently supported commands:
//! - FirmwareVersion (0x01)
//! - DeviceCapabilities (0x02)
//! - DeviceId (0x03)
//! - DeviceInfo (0x04)
//! - ExportAttestedCsr (0x0F)

use super::protocol::{
    CaliptraVdmCommand, CaliptraVdmCompletionCode, CALIPTRA_VDM_COMMAND_VERSION,
    MAX_VDM_RESPONSE_SIZE, VDM_RESPONSE_HEADER_SIZE,
};
use super::transport::{SpdmVdmDriver, SpdmVdmError};
use crate::TransportError;
use caliptra_mcu_core_util_host_command_types::*;
use zerocopy::IntoBytes;

// ---------------------------------------------------------------------------
// Helper: build VDM request, send via driver, validate response header
// ---------------------------------------------------------------------------

/// Build a VDM request [version, command, payload...], send it, and return
/// the validated response bytes (after checking header + completion code).
///
/// Returns (response_data_start_offset, total_response_len) within `resp_buf`.
fn send_vdm_request(
    command: CaliptraVdmCommand,
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    resp_buf: &mut [u8],
) -> Result<usize, TransportError> {
    // Build request: [version, command_code, payload...]
    let req_len = 2 + payload.len();
    if req_len > MAX_VDM_RESPONSE_SIZE {
        return Err(TransportError::BufferError("Request too large"));
    }
    let mut req_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    req_buf[0] = CALIPTRA_VDM_COMMAND_VERSION;
    req_buf[1] = command as u8;
    req_buf[2..2 + payload.len()].copy_from_slice(payload);

    let resp_len = driver
        .send_receive_vdm(&req_buf[..req_len], resp_buf)
        .map_err(TransportError::from)?;

    // Validate response header
    if resp_len < VDM_RESPONSE_HEADER_SIZE {
        return Err(TransportError::InvalidMessage);
    }

    let version = resp_buf[0];
    if version != CALIPTRA_VDM_COMMAND_VERSION {
        return Err(TransportError::InvalidMessage);
    }

    let resp_cmd = resp_buf[1];
    if resp_cmd != command as u8 {
        return Err(TransportError::InvalidMessage);
    }

    let cc = CaliptraVdmCompletionCode::try_from(resp_buf[2])
        .map_err(|_| TransportError::InvalidMessage)?;
    if cc != CaliptraVdmCompletionCode::Success {
        return Err(TransportError::from(SpdmVdmError::DeviceError(cc as u8)));
    }

    Ok(resp_len)
}

// ---------------------------------------------------------------------------
// FirmwareVersion (CaliptraCommandId::GetFirmwareVersion)
// ---------------------------------------------------------------------------

pub fn handle_firmware_version(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    // Parse internal request (may be empty → default to index 0)
    let _area_index = if payload.len() >= core::mem::size_of::<GetFirmwareVersionRequest>() {
        let req = GetFirmwareVersionRequest::from_bytes(payload)
            .map_err(|_| TransportError::InvalidMessage)?;
        req.index
    } else {
        0
    };

    // VDM payload for FirmwareVersion: empty (no additional data needed)
    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(
        CaliptraVdmCommand::FirmwareVersion,
        &[],
        driver,
        &mut resp_buf,
    )?;

    // Response data after header: version string bytes
    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];

    // Convert to internal response: parse version string if present
    let mut version = [0u32; 4];
    let mut commit_id = [0u8; 20];

    if !data.is_empty() {
        // Try to parse as UTF-8 version string "M.m.p commit_hash"
        if let Ok(version_str) = core::str::from_utf8(data) {
            let trimmed = version_str.trim_end_matches('\0');
            let (version_part, commit_part) = trimmed.split_once(' ').unwrap_or((trimmed, ""));
            for (i, part) in version_part.split('.').take(4).enumerate() {
                if let Ok(num) = part.parse::<u32>() {
                    version[i] = num;
                }
            }
            let cb = commit_part.as_bytes();
            let len = cb.len().min(20);
            commit_id[..len].copy_from_slice(&cb[..len]);
        }
    }

    let internal_resp = GetFirmwareVersionResponse {
        common: CommonResponse { fips_status: 0 },
        version,
        commit_id,
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// DeviceCapabilities (CaliptraCommandId::GetDeviceCapabilities)
// ---------------------------------------------------------------------------

pub fn handle_device_capabilities(
    _payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(
        CaliptraVdmCommand::DeviceCapabilities,
        &[],
        driver,
        &mut resp_buf,
    )?;

    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];

    // Response data: [capabilities(4), max_cert_size(4), max_csr_size(4), device_lifecycle(4)]
    let capabilities = if data.len() >= 4 {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    } else {
        0
    };
    let max_cert_size = if data.len() >= 8 {
        u32::from_le_bytes([data[4], data[5], data[6], data[7]])
    } else {
        0
    };
    let max_csr_size = if data.len() >= 12 {
        u32::from_le_bytes([data[8], data[9], data[10], data[11]])
    } else {
        0
    };
    let device_lifecycle = if data.len() >= 16 {
        u32::from_le_bytes([data[12], data[13], data[14], data[15]])
    } else {
        0
    };

    let internal_resp = GetDeviceCapabilitiesResponse {
        common: CommonResponse { fips_status: 0 },
        capabilities,
        max_cert_size,
        max_csr_size,
        device_lifecycle,
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// DeviceId (CaliptraCommandId::GetDeviceId)
// ---------------------------------------------------------------------------

pub fn handle_device_id(
    _payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(CaliptraVdmCommand::DeviceId, &[], driver, &mut resp_buf)?;

    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];

    // Response: [vendor_id(2), device_id(2), subsystem_vendor_id(2), subsystem_id(2)]
    let vendor_id = if data.len() >= 2 {
        u16::from_le_bytes([data[0], data[1]])
    } else {
        0
    };
    let device_id = if data.len() >= 4 {
        u16::from_le_bytes([data[2], data[3]])
    } else {
        0
    };
    let subsystem_vendor_id = if data.len() >= 6 {
        u16::from_le_bytes([data[4], data[5]])
    } else {
        0
    };
    let subsystem_id = if data.len() >= 8 {
        u16::from_le_bytes([data[6], data[7]])
    } else {
        0
    };

    let internal_resp = GetDeviceIdResponse {
        vendor_id,
        device_id,
        subsystem_vendor_id,
        subsystem_id,
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// DeviceInfo (CaliptraCommandId::GetDeviceInfo)
// ---------------------------------------------------------------------------

pub fn handle_device_info(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let info_type = if payload.len() >= core::mem::size_of::<GetDeviceInfoRequest>() {
        let req = GetDeviceInfoRequest::from_bytes(payload)
            .map_err(|_| TransportError::InvalidMessage)?;
        req.info_type
    } else {
        0
    };

    // VDM payload: [info_type as u32 LE]
    let vdm_payload = info_type.to_le_bytes();
    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(
        CaliptraVdmCommand::DeviceInfo,
        &vdm_payload,
        driver,
        &mut resp_buf,
    )?;

    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];

    let mut info_data = [0u8; 64];
    let data_len = data.len().min(64);
    info_data[..data_len].copy_from_slice(&data[..data_len]);

    let internal_resp = GetDeviceInfoResponse {
        common: CommonResponse { fips_status: 0 },
        info_length: data_len as u32,
        info_data,
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// ExportAttestedCsr (CaliptraCommandId::ExportAttestedCsr)
// ---------------------------------------------------------------------------

pub fn handle_export_attested_csr(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let req = certificate::ExportAttestedCsrRequest::from_bytes(payload)
        .map_err(|_| TransportError::InvalidMessage)?;

    // VDM payload: [device_key_id(4), algorithm(4), nonce(32)]
    let vdm_payload = req.as_bytes();

    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(
        CaliptraVdmCommand::ExportAttestedCsr,
        vdm_payload,
        driver,
        &mut resp_buf,
    )?;

    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];

    // Response data format: [data_len: u32 LE, csr_data...]
    if data.len() < 4 {
        return Err(TransportError::InvalidMessage);
    }

    let csr_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let csr_start = 4;
    let csr_end = csr_start + csr_len;

    if csr_end > data.len() {
        return Err(TransportError::BufferError(
            "ExportAttestedCsr data_len exceeds response",
        ));
    }

    let mut csr_data = [0u8; certificate::MAX_CSR_DATA_SIZE];
    let copy_csr_len = csr_len.min(certificate::MAX_CSR_DATA_SIZE);
    csr_data[..copy_csr_len].copy_from_slice(&data[csr_start..csr_start + copy_csr_len]);

    let internal_resp = certificate::ExportAttestedCsrResponse {
        common: CommonResponse { fips_status: 0 },
        data_len: csr_len as u32,
        csr_data,
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}
