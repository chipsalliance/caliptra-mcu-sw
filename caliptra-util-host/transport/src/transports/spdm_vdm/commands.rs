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
//! - GetAttestation (0x05) — recognized by the responder, handler TBD
//! - RequestDebugUnlock (0x06)
//! - AuthorizeDebugUnlockToken (0x07)
//! - ExportAttestedCsr (0x08)
//! - AuthorizedCommand (0x12)
//! - GetDotBackupBlob via DeviceOwnershipTransfer (0x11) subcommand `MDOT`

use super::protocol::{
    CaliptraVdmCommand, CaliptraVdmCompletionCode, CALIPTRA_VDM_COMMAND_VERSION,
    MAX_VDM_RESPONSE_SIZE, VDM_RESPONSE_HEADER_SIZE,
};
use super::transport::{SpdmVdmDriver, SpdmVdmError};
use crate::TransportError;
use caliptra_mcu_core_util_host_command_types::debug_unlock::{
    ProdDebugUnlockReqRequest, ProdDebugUnlockReqResponse, ProdDebugUnlockTokenRequest,
    ProdDebugUnlockTokenResponse, DEBUG_UNLOCK_CHALLENGE_SIZE, UNIQUE_DEVICE_ID_SIZE,
};
use caliptra_mcu_core_util_host_command_types::*;
use zerocopy::IntoBytes;

/// MC_GET_DOT_BACKUP_BLOB sub-command (`MDOT`) within DeviceOwnershipTransfer (0x11).
const GET_DOT_BACKUP_BLOB_CMD_ID: u32 = 0x4D44_4F54;

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
    if csr_len > certificate::MAX_CSR_DATA_SIZE {
        return Err(TransportError::BufferError(
            "ExportAttestedCsr data_len exceeds maximum CSR size",
        ));
    }

    let mut csr_data = [0u8; certificate::MAX_CSR_DATA_SIZE];
    csr_data[..csr_len].copy_from_slice(&data[csr_start..csr_end]);

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

// ---------------------------------------------------------------------------
// GetAuthCmdChallenge (CaliptraCommandId::GetAuthCmdChallenge)
// ---------------------------------------------------------------------------

/// Handle GetAuthChallenge sub-command — request a challenge nonce for HMAC authorization.
///
/// VDM wire format request:  [version, 0x12 (AuthorizedCommand), sub_cmd_id=0x4D41_4343 (4 LE)]
/// VDM wire format response: [version, 0x12 (AuthorizedCommand), completion_code, challenge(32)]
pub fn handle_get_auth_challenge(
    _payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    use caliptra_mcu_core_util_host_command_types::fuse::{
        GetAuthCmdChallengeResponse, AUTH_CMD_CHALLENGE_SIZE,
    };

    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    // Sub-command 0x4D41_4343 (MC_GET_AUTH_CMD_CHALLENGE) within AuthorizedCommand (0x12)
    let vdm_payload = 0x4D41_4343u32.to_le_bytes();
    let resp_len = send_vdm_request(
        CaliptraVdmCommand::AuthorizedCommand,
        &vdm_payload,
        driver,
        &mut resp_buf,
    )?;

    // Response data: [challenge(32)]
    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];
    if data.len() < AUTH_CMD_CHALLENGE_SIZE {
        return Err(TransportError::InvalidMessage);
    }

    let mut internal_resp = GetAuthCmdChallengeResponse::default();
    internal_resp
        .challenge
        .copy_from_slice(&data[..AUTH_CMD_CHALLENGE_SIZE]);

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// ProgramFieldEntropy (CaliptraCommandId::FeProg)
// ---------------------------------------------------------------------------

/// Handle ProgramFieldEntropy (FE_PROG) authorized sub-command.
///
/// VDM wire format request:  [version, 0x12 (AuthorizedCommand), sub_cmd_id=0x4D43_4650 (4 LE), partition(4 LE), ecc_sig(96), mldsa_sig(4627), reserved(1)]
/// VDM wire format response: [version, 0x12 (AuthorizedCommand), completion_code]
pub fn handle_fe_prog(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    use alloc::vec::Vec;
    use caliptra_mcu_core_util_host_command_types::fuse::{FeProgRequest, FeProgResponse};

    let req = FeProgRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;

    // VDM payload: [sub_cmd_id=0x4D43_4650(4 LE), partition(4 LE), ecc_sig(96), mldsa_sig(4627), reserved(1)]
    let mut vdm_payload = Vec::with_capacity(4 + size_of::<FeProgRequest>());
    vdm_payload.extend_from_slice(&MC_FE_PROG_CANONICAL_CMD_ID.to_le_bytes());
    vdm_payload.extend_from_slice(req.as_bytes());

    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let _resp_len = send_vdm_request(
        CaliptraVdmCommand::AuthorizedCommand,
        &vdm_payload,
        driver,
        &mut resp_buf,
    )?;

    // Response is header-only (completion code checked by send_vdm_request)
    let internal_resp = FeProgResponse {
        common: CommonResponse { fips_status: 0 },
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// RequestDebugUnlock (CaliptraCommandId::ProdDebugUnlockReq)
// ---------------------------------------------------------------------------

pub fn handle_prod_debug_unlock_req(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let req = ProdDebugUnlockReqRequest::from_bytes(payload)
        .map_err(|_| TransportError::InvalidMessage)?;

    // VDM payload: [unlock_level(1)]
    let vdm_payload = [req.unlock_level];
    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(
        CaliptraVdmCommand::RequestDebugUnlock,
        &vdm_payload,
        driver,
        &mut resp_buf,
    )?;

    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];

    // Response data: [unique_device_identifier(32), challenge(48)]
    if data.len() != UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE {
        return Err(TransportError::InvalidMessage);
    }

    let mut unique_device_identifier = [0u8; UNIQUE_DEVICE_ID_SIZE];
    unique_device_identifier.copy_from_slice(&data[..UNIQUE_DEVICE_ID_SIZE]);

    let mut challenge = [0u8; DEBUG_UNLOCK_CHALLENGE_SIZE];
    challenge.copy_from_slice(
        &data[UNIQUE_DEVICE_ID_SIZE..UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE],
    );

    let internal_resp = ProdDebugUnlockReqResponse {
        common: CommonResponse { fips_status: 0 },
        length: 0,
        unique_device_identifier,
        challenge,
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// GetDotBackupBlob (DeviceOwnershipTransfer sub-command)
// ---------------------------------------------------------------------------

pub fn handle_get_dot_backup_blob(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    use caliptra_mcu_core_util_host_command_types::dot::{GetDotBackupBlobResponse, DOT_BLOB_SIZE};

    if !payload.is_empty() {
        return Err(TransportError::InvalidMessage);
    }

    let sub_cmd = GET_DOT_BACKUP_BLOB_CMD_ID.to_le_bytes();
    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(
        CaliptraVdmCommand::DeviceOwnershipTransfer,
        &sub_cmd,
        driver,
        &mut resp_buf,
    )?;
    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];
    if data.len() != DOT_BLOB_SIZE {
        return Err(TransportError::InvalidMessage);
    }

    let mut blob = [0u8; DOT_BLOB_SIZE];
    blob.copy_from_slice(data);
    let internal_resp = GetDotBackupBlobResponse {
        common: CommonResponse { fips_status: 0 },
        blob,
    };

    let resp_bytes = internal_resp.as_bytes();
    if resp_bytes.len() > response_buffer.len() {
        return Err(TransportError::BufferError("response buffer too small"));
    }
    response_buffer[..resp_bytes.len()].copy_from_slice(resp_bytes);
    Ok(resp_bytes.len())
}

// ---------------------------------------------------------------------------
// AuthorizeDebugUnlockToken (CaliptraCommandId::ProdDebugUnlockToken)
// ---------------------------------------------------------------------------

pub fn handle_prod_debug_unlock_token(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let req = ProdDebugUnlockTokenRequest::from_bytes(payload)
        .map_err(|_| TransportError::InvalidMessage)?;

    // The request already carries the Caliptra mailbox checksum as its first
    // word, allowing the MCU to stream it without buffering the whole token.
    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let _resp_len = send_vdm_request(
        CaliptraVdmCommand::AuthorizeDebugUnlockToken,
        req.as_bytes(),
        driver,
        &mut resp_buf,
    )?;

    // Response is just completion code (already validated by send_vdm_request)
    let internal_resp = ProdDebugUnlockTokenResponse {
        common: CommonResponse { fips_status: 0 },
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use caliptra_mcu_core_util_host_command_types::dot;
    use std::vec;
    use std::vec::Vec;
    use zerocopy::IntoBytes;

    struct FakeDriver {
        response: Vec<u8>,
        last_request: Vec<u8>,
    }

    impl SpdmVdmDriver for FakeDriver {
        fn send_receive_vdm(
            &mut self,
            request: &[u8],
            response: &mut [u8],
        ) -> Result<usize, SpdmVdmError> {
            self.last_request.clear();
            self.last_request.extend_from_slice(request);
            response[..self.response.len()].copy_from_slice(&self.response);
            Ok(self.response.len())
        }

        fn is_ready(&self) -> bool {
            true
        }

        fn connect(&mut self) -> Result<(), SpdmVdmError> {
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), SpdmVdmError> {
            Ok(())
        }
    }

    fn success_response(command: CaliptraVdmCommand, data: &[u8]) -> Vec<u8> {
        let mut response = vec![CALIPTRA_VDM_COMMAND_VERSION, command as u8, 0];
        response.extend_from_slice(data);
        response
    }

    #[test]
    fn debug_unlock_token_preserves_caliptra_mailbox_request() {
        let mut req = ProdDebugUnlockTokenRequest {
            length: 1,
            unlock_level: 2,
            ..Default::default()
        };
        req.populate_checksum();
        let mut driver = FakeDriver {
            response: success_response(CaliptraVdmCommand::AuthorizeDebugUnlockToken, &[]),
            last_request: Vec::new(),
        };
        let mut response_buffer = [0u8; core::mem::size_of::<ProdDebugUnlockTokenResponse>()];

        handle_prod_debug_unlock_token(req.as_bytes(), &mut driver, &mut response_buffer)
            .expect("DebugUnlock token should be accepted");

        assert_eq!(
            &driver.last_request[..2],
            &[
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::AuthorizeDebugUnlockToken as u8,
            ]
        );
        assert_eq!(&driver.last_request[2..], req.as_bytes());
    }

    #[test]
    fn get_dot_backup_blob_sends_dot_subcommand_and_decodes_fixed_blob() {
        let blob = [0x5Au8; dot::DOT_BLOB_SIZE];
        let mut driver = FakeDriver {
            response: success_response(CaliptraVdmCommand::DeviceOwnershipTransfer, &blob),
            last_request: Vec::new(),
        };
        let mut response_buffer = vec![0; core::mem::size_of::<dot::GetDotBackupBlobResponse>()];

        let len = handle_get_dot_backup_blob(&[], &mut driver, &mut response_buffer)
            .expect("DOT backup blob request should succeed");

        assert_eq!(
            driver.last_request,
            vec![
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::DeviceOwnershipTransfer as u8,
                0x54,
                0x4F,
                0x44,
                0x4D,
            ]
        );
        assert_eq!(len, core::mem::size_of::<dot::GetDotBackupBlobResponse>());
        assert_eq!(&response_buffer[4..4 + dot::DOT_BLOB_SIZE], &blob);
    }

    #[test]
    fn get_dot_backup_blob_rejects_partial_blob_response() {
        let blob = [0x5Au8; dot::DOT_BLOB_SIZE - 1];
        let mut driver = FakeDriver {
            response: success_response(CaliptraVdmCommand::DeviceOwnershipTransfer, &blob),
            last_request: Vec::new(),
        };
        let mut response_buffer = vec![0; core::mem::size_of::<dot::GetDotBackupBlobResponse>()];

        let err = handle_get_dot_backup_blob(&[], &mut driver, &mut response_buffer)
            .expect_err("partial DOT_BLOB response must be rejected");
        assert!(matches!(err, TransportError::InvalidMessage));
    }

    #[test]
    fn get_dot_backup_blob_rejects_short_response_buffer() {
        let blob = [0x5Au8; dot::DOT_BLOB_SIZE];
        let mut driver = FakeDriver {
            response: success_response(CaliptraVdmCommand::DeviceOwnershipTransfer, &blob),
            last_request: Vec::new(),
        };
        let mut response_buffer =
            vec![0; core::mem::size_of::<dot::GetDotBackupBlobResponse>() - 1];

        let err = handle_get_dot_backup_blob(&[], &mut driver, &mut response_buffer)
            .expect_err("short internal response buffer must be rejected");
        match err {
            TransportError::BufferError(msg) => assert!(msg.contains("response buffer too small")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn get_dot_backup_blob_rejects_non_empty_payload() {
        let mut driver = FakeDriver {
            response: success_response(
                CaliptraVdmCommand::DeviceOwnershipTransfer,
                &[0x5A; dot::DOT_BLOB_SIZE],
            ),
            last_request: Vec::new(),
        };
        let mut response_buffer = vec![0; core::mem::size_of::<dot::GetDotBackupBlobResponse>()];

        let err = handle_get_dot_backup_blob(&[0], &mut driver, &mut response_buffer)
            .expect_err("GetDotBackupBlob request payload must be empty");
        assert!(matches!(err, TransportError::InvalidMessage));
    }

    #[test]
    fn export_attested_csr_rejects_oversized_csr_len() {
        let req = certificate::ExportAttestedCsrRequest {
            device_key_id: 1,
            algorithm: 1,
            nonce: [0xAB; 32],
        };
        let oversized_len = (certificate::MAX_CSR_DATA_SIZE + 1) as u32;
        let mut data = Vec::new();
        data.extend_from_slice(&oversized_len.to_le_bytes());
        data.resize(4 + certificate::MAX_CSR_DATA_SIZE + 1, 0xA5);
        let mut driver = FakeDriver {
            response: success_response(CaliptraVdmCommand::ExportAttestedCsr, &data),
            last_request: Vec::new(),
        };
        let mut response_buffer =
            vec![0; core::mem::size_of::<certificate::ExportAttestedCsrResponse>()];

        let err = handle_export_attested_csr(req.as_bytes(), &mut driver, &mut response_buffer)
            .expect_err("oversized CSR response must be rejected");

        match err {
            TransportError::BufferError(msg) => assert!(msg.contains("maximum CSR size")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn debug_unlock_req_rejects_trailing_response_bytes() {
        let req = ProdDebugUnlockReqRequest::new(1);
        let mut data = vec![0xA5; UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE + 1];
        let mut driver = FakeDriver {
            response: success_response(CaliptraVdmCommand::RequestDebugUnlock, &data),
            last_request: Vec::new(),
        };
        let mut response_buffer = [0u8; core::mem::size_of::<ProdDebugUnlockReqResponse>()];

        let err = handle_prod_debug_unlock_req(req.as_bytes(), &mut driver, &mut response_buffer)
            .expect_err("DebugUnlock response with trailing bytes must be rejected");

        assert!(matches!(err, TransportError::InvalidMessage));
        data.truncate(UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE);
        driver.response = success_response(CaliptraVdmCommand::RequestDebugUnlock, &data);
        handle_prod_debug_unlock_req(req.as_bytes(), &mut driver, &mut response_buffer)
            .expect("exact-length DebugUnlock response should be accepted");
        assert_eq!(
            driver.last_request,
            [
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::RequestDebugUnlock as u8,
                req.unlock_level,
            ]
        );
    }
}
