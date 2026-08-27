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
//! - GetAttestation (0x05)
//! - RequestDebugUnlock (0x06)
//! - AuthorizeDebugUnlockToken (0x07)
//! - ExportAttestedCsr (0x08)
//! - DeviceOwnershipTransfer (0x11)
//! - AuthorizedCommand (0x12)

use super::protocol::{
    CaliptraVdmCommand, CaliptraVdmCompletionCode, CALIPTRA_VDM_COMMAND_VERSION,
    MAX_VDM_RESPONSE_SIZE, VDM_RESPONSE_HEADER_SIZE,
};
use super::transport::{SpdmVdmDriver, SpdmVdmError};
use crate::TransportError;
use alloc::vec::Vec;
use caliptra_mcu_core_util_host_command_types::debug_unlock::{
    ProdDebugUnlockReqRequest, ProdDebugUnlockReqResponse, ProdDebugUnlockTokenRequest,
    ProdDebugUnlockTokenResponse, DEBUG_UNLOCK_CHALLENGE_SIZE, UNIQUE_DEVICE_ID_SIZE,
};
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

fn send_dot_request(
    command: CaliptraVdmCommand,
    subcommand: u32,
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
) -> Result<Vec<u8>, TransportError> {
    // Caliptra VDM payload dwords are little-endian even though their numeric
    // constants are written as readable ASCII FourCC values.
    let mut vdm_payload = Vec::with_capacity(4 + payload.len());
    vdm_payload.extend_from_slice(&subcommand.to_le_bytes());
    vdm_payload.extend_from_slice(payload);

    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(command, &vdm_payload, driver, &mut resp_buf)?;
    Ok(resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len].to_vec())
}

fn send_authorized_dot_request(
    subcommand: u32,
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
) -> Result<Vec<u8>, TransportError> {
    // AuthorizedCommand expects the DOT family first; send_dot_request then
    // prepends that family to produce [family 0x11][FourCC][payload][trailer].
    let mut family_payload = Vec::with_capacity(4 + payload.len());
    family_payload.extend_from_slice(&subcommand.to_le_bytes());
    family_payload.extend_from_slice(payload);
    send_dot_request(
        CaliptraVdmCommand::AuthorizedCommand,
        DOT_FAMILY_ID,
        &family_payload,
        driver,
    )
}

fn write_dot_transition_response(
    data: &[u8],
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    if !data.is_empty() {
        return Err(TransportError::InvalidMessage);
    }

    let internal_resp = DotTransitionResponse {
        common: CommonResponse { fips_status: 0 },
        reset_required: 1,
    };
    let resp_bytes = internal_resp.as_bytes();
    if response_buffer.len() < resp_bytes.len() {
        return Err(TransportError::BufferError("Response buffer too small"));
    }
    response_buffer[..resp_bytes.len()].copy_from_slice(resp_bytes);
    Ok(resp_bytes.len())
}

// ---------------------------------------------------------------------------
// DeviceOwnershipTransfer (CaliptraVdmCommand::DeviceOwnershipTransfer)
// ---------------------------------------------------------------------------

pub fn handle_dot_lock(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let request =
        DotLockRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;
    let data =
        send_authorized_dot_request(MC_DOT_LOCK_CANONICAL_CMD_ID, request.as_bytes(), driver)?;
    write_dot_transition_response(&data, response_buffer)
}

pub fn handle_dot_disable(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let request =
        DotDisableRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;
    let data =
        send_authorized_dot_request(MC_DOT_DISABLE_CANONICAL_CMD_ID, request.as_bytes(), driver)?;
    write_dot_transition_response(&data, response_buffer)
}

pub fn handle_dot_rotate(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let request =
        DotRotateRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;
    let data =
        send_authorized_dot_request(MC_DOT_ROTATE_CANONICAL_CMD_ID, request.as_bytes(), driver)?;
    write_dot_transition_response(&data, response_buffer)
}

pub fn handle_dot_unlock_challenge(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    DotUnlockChallengeRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;

    let challenge = send_dot_request(
        CaliptraVdmCommand::DeviceOwnershipTransfer,
        MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID,
        &[],
        driver,
    )?;
    if challenge.len() != AUTH_CMD_NONCE_LEN {
        return Err(TransportError::InvalidMessage);
    }

    let mut internal_resp = DotChallengeResponse::default();
    internal_resp.challenge.copy_from_slice(&challenge);
    let resp_bytes = internal_resp.as_bytes();
    if response_buffer.len() < resp_bytes.len() {
        return Err(TransportError::BufferError("Response buffer too small"));
    }
    response_buffer[..resp_bytes.len()].copy_from_slice(resp_bytes);
    Ok(resp_bytes.len())
}

pub fn handle_dot_unlock(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let request =
        DotUnlockRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;
    let data = send_dot_request(
        CaliptraVdmCommand::DeviceOwnershipTransfer,
        MC_DOT_UNLOCK_CANONICAL_CMD_ID,
        request.as_bytes(),
        driver,
    )?;
    write_dot_transition_response(&data, response_buffer)
}

pub fn handle_get_dot_backup_blob(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let request =
        GetDotBackupBlobRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;
    let data = send_authorized_dot_request(
        MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID,
        request.as_bytes(),
        driver,
    )?;
    if data.len() != DOT_BLOB_SIZE {
        return Err(TransportError::InvalidMessage);
    }
    let response = GetDotBackupBlobResponse {
        common: CommonResponse { fips_status: 0 },
        blob: data
            .try_into()
            .map_err(|_| TransportError::InvalidMessage)?,
    };
    let bytes = response.as_bytes();
    if response_buffer.len() < bytes.len() {
        return Err(TransportError::BufferError("Response buffer too small"));
    }
    response_buffer[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

pub fn handle_dot_status(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    DotStatusRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;
    let data = send_dot_request(
        CaliptraVdmCommand::DeviceOwnershipTransfer,
        MC_DOT_STATUS_CANONICAL_CMD_ID,
        &[],
        driver,
    )?;
    if data.len() != 4 {
        return Err(TransportError::InvalidMessage);
    }
    let response = DotStatusResponse {
        common: CommonResponse { fips_status: 0 },
        status: DotStatus {
            enabled: data[0],
            locked: data[1],
            burned: u16::from_le_bytes([data[2], data[3]]),
        },
    };
    let bytes = response.as_bytes();
    if response_buffer.len() < bytes.len() {
        return Err(TransportError::BufferError("Response buffer too small"));
    }
    response_buffer[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

pub fn handle_dot_recovery(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let request =
        DotRecoveryRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;
    let data = send_dot_request(
        CaliptraVdmCommand::DeviceOwnershipTransfer,
        MC_DOT_RECOVERY_CANONICAL_CMD_ID,
        &request.blob,
        driver,
    )?;
    write_dot_transition_response(&data, response_buffer)
}

pub fn handle_dot_override_challenge(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let request = DotOverrideChallengeRequest::from_bytes(payload)
        .map_err(|_| TransportError::InvalidMessage)?;
    let challenge = send_dot_request(
        CaliptraVdmCommand::DeviceOwnershipTransfer,
        MC_DOT_OVERRIDE_CHALLENGE_CANONICAL_CMD_ID,
        request.as_bytes(),
        driver,
    )?;
    if challenge.len() != AUTH_CMD_NONCE_LEN {
        return Err(TransportError::InvalidMessage);
    }
    let response = DotChallengeResponse {
        common: CommonResponse { fips_status: 0 },
        challenge: challenge
            .try_into()
            .map_err(|_| TransportError::InvalidMessage)?,
    };
    let bytes = response.as_bytes();
    if response_buffer.len() < bytes.len() {
        return Err(TransportError::BufferError("Response buffer too small"));
    }
    response_buffer[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

pub fn handle_dot_override(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let request =
        DotOverrideRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;
    let data = send_dot_request(
        CaliptraVdmCommand::DeviceOwnershipTransfer,
        MC_DOT_OVERRIDE_CANONICAL_CMD_ID,
        request.as_bytes(),
        driver,
    )?;
    write_dot_transition_response(&data, response_buffer)
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
// GetAttestation (CaliptraCommandId::GetAttestation)
// ---------------------------------------------------------------------------

/// Encode a `GET_ATTESTATION` request and decode the evidence response.
///
/// The device may answer either inline or over the SPDM chunked large-response
/// path; both arrive here already reassembled by the driver, so this only has
/// to parse the framed payload.
///
/// Response data (after the 3-byte VDM header) is:
///   `[evidence_format: u32 LE, data_len: u32 LE, data...]`
///
/// A discovery query (`evidence_format == 0` in the request) echoes format 0
/// and carries a 4-byte supported-format bitmap in `data`.
pub fn handle_get_attestation(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let req = attestation::GetAttestationRequest::from_bytes(payload)
        .map_err(|_| TransportError::InvalidMessage)?;

    // VDM payload: [evidence_format(4), algorithm(4), pki_entity_slot(4), nonce(32)]
    let vdm_payload = req.as_bytes();

    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(
        CaliptraVdmCommand::GetAttestation,
        vdm_payload,
        driver,
        &mut resp_buf,
    )?;

    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];

    // Response fields precede the evidence: [evidence_format(4), data_len(4)]
    const RESP_FIELDS_LEN: usize = 8;
    if data.len() < RESP_FIELDS_LEN {
        return Err(TransportError::InvalidMessage);
    }

    let evidence_format = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let evidence_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let evidence_end = RESP_FIELDS_LEN + evidence_len;

    if evidence_end > data.len() {
        return Err(TransportError::BufferError(
            "GetAttestation data_len exceeds response",
        ));
    }
    // Signed evidence that is silently truncated is unverifiable rather than
    // merely short, so reject instead of clamping.
    if evidence_len > attestation::MAX_ATTESTATION_DATA_SIZE {
        return Err(TransportError::BufferError(
            "GetAttestation data_len exceeds maximum evidence size",
        ));
    }

    let mut evidence = [0u8; attestation::MAX_ATTESTATION_DATA_SIZE];
    evidence[..evidence_len].copy_from_slice(&data[RESP_FIELDS_LEN..evidence_end]);

    let internal_resp = attestation::GetAttestationResponse {
        common: CommonResponse { fips_status: 0 },
        evidence_format,
        data_len: evidence_len as u32,
        data: evidence,
    };

    let resp_bytes = internal_resp.as_bytes();
    if response_buffer.len() < resp_bytes.len() {
        return Err(TransportError::BufferError(
            "GetAttestation response buffer too small",
        ));
    }
    response_buffer[..resp_bytes.len()].copy_from_slice(resp_bytes);
    Ok(resp_bytes.len())
}

// ---------------------------------------------------------------------------
// GetAuthCmdChallenge (CaliptraCommandId::GetAuthCmdChallenge)
// ---------------------------------------------------------------------------

/// Handle GetAuthChallenge sub-command — request a one-use authorization nonce.
///
/// VDM wire format request:  [version, 0x12 (AuthorizedCommand), sub_cmd_id=0x4D41_4343 (4 LE)]
/// VDM wire format response: [version, 0x12 (AuthorizedCommand), completion_code, challenge(48)]
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

    // Response data: [challenge(48)]
    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];
    if data.len() != AUTH_CMD_CHALLENGE_SIZE {
        return Err(TransportError::InvalidMessage);
    }

    let mut internal_resp = GetAuthCmdChallengeResponse::default();
    internal_resp
        .challenge
        .copy_from_slice(&data[..AUTH_CMD_CHALLENGE_SIZE]);

    let resp_bytes = internal_resp.as_bytes();
    if response_buffer.len() < resp_bytes.len() {
        return Err(TransportError::BufferError("Response buffer too small"));
    }
    response_buffer[..resp_bytes.len()].copy_from_slice(resp_bytes);
    Ok(resp_bytes.len())
}

fn handle_authorized_fuse_command(
    command_id: u32,
    request: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    let mut vdm_payload = Vec::with_capacity(4 + request.len());
    vdm_payload.extend_from_slice(&command_id.to_le_bytes());
    vdm_payload.extend_from_slice(request);
    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(
        CaliptraVdmCommand::AuthorizedCommand,
        &vdm_payload,
        driver,
        &mut resp_buf,
    )?;
    if resp_len != VDM_RESPONSE_HEADER_SIZE {
        return Err(TransportError::InvalidMessage);
    }
    let response = CommonResponse { fips_status: 0 };
    if response_buffer.len() < response.as_bytes().len() {
        return Err(TransportError::BufferError("Response buffer too small"));
    }
    response_buffer[..response.as_bytes().len()].copy_from_slice(response.as_bytes());
    Ok(response.as_bytes().len())
}

// ---------------------------------------------------------------------------
// Authorized fuse commands
// ---------------------------------------------------------------------------

/// Handle ProgramFieldEntropy (FE_PROG) authorized sub-command.
///
/// VDM wire format request: [version, 0x12, sub_cmd_id, partition,
/// nonce, ECC public key, ML-DSA public key, HybridSignature].
/// VDM wire format response: [version, 0x12 (AuthorizedCommand), completion_code]
pub fn handle_fe_prog(
    payload: &[u8],
    driver: &mut dyn SpdmVdmDriver,
    response_buffer: &mut [u8],
) -> Result<usize, TransportError> {
    use caliptra_mcu_core_util_host_command_types::fuse::{FeProgRequest, FeProgResponse};
    let req = FeProgRequest::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;
    let mut vdm_payload = Vec::with_capacity(4 + size_of::<FeProgRequest>());
    vdm_payload.extend_from_slice(&MC_FE_PROG_CANONICAL_CMD_ID.to_le_bytes());
    vdm_payload.extend_from_slice(req.as_bytes());
    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    send_vdm_request(
        CaliptraVdmCommand::AuthorizedCommand,
        &vdm_payload,
        driver,
        &mut resp_buf,
    )?;
    let response = FeProgResponse {
        common: CommonResponse { fips_status: 0 },
    };
    let bytes = response.as_bytes();
    if response_buffer.len() < bytes.len() {
        return Err(TransportError::BufferError("Response buffer too small"));
    }
    response_buffer[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

macro_rules! authorized_fuse_handler {
    ($name:ident, $request:ty, $command_id:expr) => {
        pub fn $name(
            payload: &[u8],
            driver: &mut dyn SpdmVdmDriver,
            response_buffer: &mut [u8],
        ) -> Result<usize, TransportError> {
            let req =
                <$request>::from_bytes(payload).map_err(|_| TransportError::InvalidMessage)?;
            handle_authorized_fuse_command($command_id, req.as_bytes(), driver, response_buffer)
        }
    };
}
authorized_fuse_handler!(
    handle_provision_vendor_pk_hash,
    fuse::ProvisionVendorPkHashRequest,
    fuse::MC_PROVISION_VENDOR_PK_HASH_CANONICAL_CMD_ID
);
authorized_fuse_handler!(
    handle_fuse_increase_caliptra_min_svn,
    fuse::FuseIncreaseCaliptraMinSvnRequest,
    fuse::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN_CANONICAL_CMD_ID
);
authorized_fuse_handler!(
    handle_fuse_revoke_vendor_pub_key,
    fuse::FuseRevokeVendorPubKeyRequest,
    fuse::MC_FUSE_REVOKE_VENDOR_PUB_KEY_CANONICAL_CMD_ID
);
authorized_fuse_handler!(
    handle_fuse_revoke_vendor_pk_hash,
    fuse::FuseRevokeVendorPkHashRequest,
    fuse::MC_FUSE_REVOKE_VENDOR_PK_HASH_CANONICAL_CMD_ID
);
authorized_fuse_handler!(
    handle_fuse_lock_partition,
    fuse::FuseLockPartitionRequest,
    fuse::MC_FUSE_LOCK_PARTITION_CANONICAL_CMD_ID
);
authorized_fuse_handler!(
    handle_provision_owner_pk_hash,
    fuse::ProvisionOwnerPkHashRequest,
    fuse::MC_PROVISION_OWNER_PK_HASH_CANONICAL_CMD_ID
);

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

    let mut resp_buf = [0u8; MAX_VDM_RESPONSE_SIZE];
    let resp_len = send_vdm_request(
        CaliptraVdmCommand::RequestDebugUnlock,
        req.as_bytes(),
        driver,
        &mut resp_buf,
    )?;

    let data = &resp_buf[VDM_RESPONSE_HEADER_SIZE..resp_len];

    const RESPONSE_LENGTH_DWORDS: u32 = 21;
    const LENGTH_SIZE: usize = core::mem::size_of::<u32>();
    if data.len() != LENGTH_SIZE + UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE {
        return Err(TransportError::InvalidMessage);
    }
    let length = u32::from_le_bytes(
        data[..LENGTH_SIZE]
            .try_into()
            .map_err(|_| TransportError::InvalidMessage)?,
    );
    if length != RESPONSE_LENGTH_DWORDS {
        return Err(TransportError::InvalidMessage);
    }

    let mut unique_device_identifier = [0u8; UNIQUE_DEVICE_ID_SIZE];
    unique_device_identifier
        .copy_from_slice(&data[LENGTH_SIZE..LENGTH_SIZE + UNIQUE_DEVICE_ID_SIZE]);

    let mut challenge = [0u8; DEBUG_UNLOCK_CHALLENGE_SIZE];
    challenge.copy_from_slice(
        &data[LENGTH_SIZE + UNIQUE_DEVICE_ID_SIZE
            ..LENGTH_SIZE + UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE],
    );

    let internal_resp = ProdDebugUnlockReqResponse {
        common: CommonResponse { fips_status: 0 },
        length,
        unique_device_identifier,
        challenge,
    };

    let resp_bytes = internal_resp.as_bytes();
    let copy_len = resp_bytes.len().min(response_buffer.len());
    response_buffer[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
    Ok(copy_len)
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
    use crate::transports::spdm_vdm::dispatch::VdmCommandHandlerFn;
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

    fn attestation_response(evidence_format: u32, evidence: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&evidence_format.to_le_bytes());
        data.extend_from_slice(&(evidence.len() as u32).to_le_bytes());
        data.extend_from_slice(evidence);
        success_response(CaliptraVdmCommand::GetAttestation, &data)
    }

    #[test]
    fn get_attestation_encodes_request_and_decodes_evidence() {
        let evidence = vec![0xA5u8; 512];
        let req = attestation::GetAttestationRequest::new(
            attestation::EvidenceFormat::PcrQuote,
            attestation::AsymAlgo::EccP384,
            attestation::PkiEntitySlot::Vendor,
            &[0x42u8; 32],
        );
        let mut driver = FakeDriver {
            response: attestation_response(attestation::EvidenceFormat::PcrQuote as u32, &evidence),
            last_request: Vec::new(),
        };
        let mut response_buffer =
            vec![0u8; core::mem::size_of::<attestation::GetAttestationResponse>()];

        let written = handle_get_attestation(req.as_bytes(), &mut driver, &mut response_buffer)
            .expect("GetAttestation should be accepted");
        assert_eq!(written, response_buffer.len());

        assert_eq!(
            &driver.last_request[..2],
            &[
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::GetAttestation as u8,
            ]
        );
        assert_eq!(&driver.last_request[2..], req.as_bytes());

        let resp = attestation::GetAttestationResponse::read_from_bytes(&response_buffer).unwrap();
        assert_eq!(
            resp.validate_evidence_payload(attestation::EvidenceFormat::PcrQuote),
            Ok(evidence.len())
        );
        assert_eq!(resp.evidence_bytes(), &evidence[..]);
    }

    #[test]
    fn get_attestation_query_returns_supported_format_bitmap() {
        let bitmap = attestation::EvidenceFormat::OcpEat.bit();
        let mut driver = FakeDriver {
            response: attestation_response(
                attestation::EVIDENCE_FORMAT_QUERY,
                &bitmap.to_le_bytes(),
            ),
            last_request: Vec::new(),
        };
        let mut response_buffer =
            vec![0u8; core::mem::size_of::<attestation::GetAttestationResponse>()];

        handle_get_attestation(
            attestation::GetAttestationRequest::query().as_bytes(),
            &mut driver,
            &mut response_buffer,
        )
        .expect("format query should be accepted");

        let resp = attestation::GetAttestationResponse::read_from_bytes(&response_buffer).unwrap();
        assert_eq!(resp.supported_formats(), Ok(bitmap));
    }

    #[test]
    fn get_attestation_rejects_data_len_beyond_response() {
        // Claim more evidence than the frame actually carries.
        let mut response =
            attestation_response(attestation::EvidenceFormat::OcpEat as u32, &[0x11u8; 16]);
        let len_at = VDM_RESPONSE_HEADER_SIZE + 4;
        response[len_at..len_at + 4].copy_from_slice(&4096u32.to_le_bytes());

        let mut driver = FakeDriver {
            response,
            last_request: Vec::new(),
        };
        let mut response_buffer =
            vec![0u8; core::mem::size_of::<attestation::GetAttestationResponse>()];

        assert!(handle_get_attestation(
            attestation::GetAttestationRequest::query().as_bytes(),
            &mut driver,
            &mut response_buffer,
        )
        .is_err());
    }

    #[test]
    fn get_attestation_rejects_undersized_response_buffer() {
        let mut driver = FakeDriver {
            response: attestation_response(
                attestation::EvidenceFormat::OcpEat as u32,
                &[0x11u8; 16],
            ),
            last_request: Vec::new(),
        };
        // Truncating signed evidence makes it unverifiable, so this must fail
        // rather than return a short response.
        let mut response_buffer = [0u8; 64];

        assert!(handle_get_attestation(
            attestation::GetAttestationRequest::query().as_bytes(),
            &mut driver,
            &mut response_buffer,
        )
        .is_err());
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
    fn authorized_fuse_commands_preserve_exact_wire_layout() {
        let mut sig = caliptra_mcu_mbox_common::messages::HybridSignature::default();
        sig.ecc_sig_r.fill(0x11);
        sig.ecc_sig_s.fill(0x22);
        sig.mldsa_sig.fill(0x33);

        let pvpk = fuse::ProvisionVendorPkHashRequest {
            slot: 0x0102_0304,
            hash: [0xA5; 48],
            sig: sig.clone(),
            nonce: [0; fuse::AUTH_CMD_CHALLENGE_SIZE],
            ecc_pub_x: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            ecc_pub_y: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            mldsa_pub: [0; fuse::AUTH_PUB_MLDSA_SIZE],
        };
        let mcms = fuse::FuseIncreaseCaliptraMinSvnRequest {
            flags: 0x1122_3344,
            svn: 0x5566_7788,
            sig: sig.clone(),
            nonce: [0; fuse::AUTH_CMD_CHALLENGE_SIZE],
            ecc_pub_x: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            ecc_pub_y: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            mldsa_pub: [0; fuse::AUTH_PUB_MLDSA_SIZE],
        };
        let mrvk = fuse::FuseRevokeVendorPubKeyRequest {
            reserved: 0x0102_0304,
            vendor_pk_hash_slot: 0x1112_1314,
            key_type: 0x2122_2324,
            key_index: 0x3132_3334,
            sig: sig.clone(),
            nonce: [0; fuse::AUTH_CMD_CHALLENGE_SIZE],
            ecc_pub_x: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            ecc_pub_y: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            mldsa_pub: [0; fuse::AUTH_PUB_MLDSA_SIZE],
        };
        let rvkh = fuse::FuseRevokeVendorPkHashRequest {
            reserved: 0x4142_4344,
            vendor_pk_hash_slot: 0x5152_5354,
            sig: sig.clone(),
            nonce: [0; fuse::AUTH_CMD_CHALLENGE_SIZE],
            ecc_pub_x: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            ecc_pub_y: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            mldsa_pub: [0; fuse::AUTH_PUB_MLDSA_SIZE],
        };
        let ifpk = fuse::FuseLockPartitionRequest {
            partition: 0x6162_6364,
            sig: sig.clone(),
            nonce: [0; fuse::AUTH_CMD_CHALLENGE_SIZE],
            ecc_pub_x: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            ecc_pub_y: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            mldsa_pub: [0; fuse::AUTH_PUB_MLDSA_SIZE],
        };
        let popk = fuse::ProvisionOwnerPkHashRequest {
            hash: [0xC3; 48],
            sig: sig.clone(),
            nonce: [0; fuse::AUTH_CMD_CHALLENGE_SIZE],
            ecc_pub_x: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            ecc_pub_y: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            mldsa_pub: [0; fuse::AUTH_PUB_MLDSA_SIZE],
        };

        let signature_bytes = {
            let mut bytes = vec![0x11; 48];
            bytes.extend_from_slice(&[0x22; 48]);
            bytes.extend_from_slice(&vec![0x33; sig.mldsa_sig.len()]);
            bytes
        };
        let make_golden = |command_id: u32, fields: &[u8]| {
            let mut packet = vec![
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::AuthorizedCommand as u8,
            ];
            packet.extend_from_slice(&command_id.to_le_bytes());
            packet.extend_from_slice(fields);
            packet.extend_from_slice(&[0u8; fuse::AUTH_CMD_CHALLENGE_SIZE]);
            packet.extend_from_slice(&[0u8; fuse::AUTH_PUB_ECC_COORD_SIZE]);
            packet.extend_from_slice(&[0u8; fuse::AUTH_PUB_ECC_COORD_SIZE]);
            packet.extend_from_slice(&[0u8; fuse::AUTH_PUB_MLDSA_SIZE]);
            packet.extend_from_slice(&signature_bytes);
            packet
        };

        let mut pvpk_fields = 0x0102_0304u32.to_le_bytes().to_vec();
        pvpk_fields.extend_from_slice(&[0xA5; 48]);
        let mut mcms_fields = 0x1122_3344u32.to_le_bytes().to_vec();
        mcms_fields.extend_from_slice(&0x5566_7788u32.to_le_bytes());
        let mut mrvk_fields = Vec::new();
        for field in [0x0102_0304u32, 0x1112_1314, 0x2122_2324, 0x3132_3334] {
            mrvk_fields.extend_from_slice(&field.to_le_bytes());
        }
        let mut rvkh_fields = 0x4142_4344u32.to_le_bytes().to_vec();
        rvkh_fields.extend_from_slice(&0x5152_5354u32.to_le_bytes());
        let ifpk_fields = 0x6162_6364u32.to_le_bytes();
        let popk_fields = [0xC3; 48];

        let cases: Vec<(&[u8], Vec<u8>, VdmCommandHandlerFnForTest)> = vec![
            (
                pvpk.as_bytes(),
                make_golden(
                    fuse::MC_PROVISION_VENDOR_PK_HASH_CANONICAL_CMD_ID,
                    &pvpk_fields,
                ),
                handle_provision_vendor_pk_hash,
            ),
            (
                mcms.as_bytes(),
                make_golden(
                    fuse::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN_CANONICAL_CMD_ID,
                    &mcms_fields,
                ),
                handle_fuse_increase_caliptra_min_svn,
            ),
            (
                mrvk.as_bytes(),
                make_golden(
                    fuse::MC_FUSE_REVOKE_VENDOR_PUB_KEY_CANONICAL_CMD_ID,
                    &mrvk_fields,
                ),
                handle_fuse_revoke_vendor_pub_key,
            ),
            (
                rvkh.as_bytes(),
                make_golden(
                    fuse::MC_FUSE_REVOKE_VENDOR_PK_HASH_CANONICAL_CMD_ID,
                    &rvkh_fields,
                ),
                handle_fuse_revoke_vendor_pk_hash,
            ),
            (
                ifpk.as_bytes(),
                make_golden(fuse::MC_FUSE_LOCK_PARTITION_CANONICAL_CMD_ID, &ifpk_fields),
                handle_fuse_lock_partition,
            ),
            (
                popk.as_bytes(),
                make_golden(
                    fuse::MC_PROVISION_OWNER_PK_HASH_CANONICAL_CMD_ID,
                    &popk_fields,
                ),
                handle_provision_owner_pk_hash,
            ),
        ];

        for (request, golden, handler) in cases {
            let mut driver = FakeDriver {
                response: success_response(CaliptraVdmCommand::AuthorizedCommand, &[]),
                last_request: Vec::new(),
            };
            let mut response = [0u8; core::mem::size_of::<CommonResponse>()];
            handler(request, &mut driver, &mut response).unwrap();
            assert_eq!(driver.last_request, golden);

            let err = handler(&request[..request.len() - 1], &mut driver, &mut response)
                .expect_err("truncated hybrid signature must be rejected locally");
            assert!(matches!(err, TransportError::InvalidMessage));

            let mut oversized = request.to_vec();
            oversized.push(0);
            let err = handler(&oversized, &mut driver, &mut response)
                .expect_err("trailing request bytes must be rejected locally");
            assert!(matches!(err, TransportError::InvalidMessage));
        }
    }

    type VdmCommandHandlerFnForTest =
        fn(&[u8], &mut dyn SpdmVdmDriver, &mut [u8]) -> Result<usize, TransportError>;

    #[test]
    fn authorized_command_rejects_trailing_response_and_small_output_buffer() {
        let req = fuse::FuseIncreaseCaliptraMinSvnRequest {
            flags: 0,
            svn: 1,
            sig: Default::default(),
            nonce: [0; fuse::AUTH_CMD_CHALLENGE_SIZE],
            ecc_pub_x: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            ecc_pub_y: [0; fuse::AUTH_PUB_ECC_COORD_SIZE],
            mldsa_pub: [0; fuse::AUTH_PUB_MLDSA_SIZE],
        };
        let mut driver = FakeDriver {
            response: success_response(CaliptraVdmCommand::AuthorizedCommand, &[0xAA]),
            last_request: Vec::new(),
        };
        let mut response = [0u8; core::mem::size_of::<CommonResponse>()];
        assert!(matches!(
            handle_fuse_increase_caliptra_min_svn(req.as_bytes(), &mut driver, &mut response),
            Err(TransportError::InvalidMessage)
        ));

        driver.response = success_response(CaliptraVdmCommand::AuthorizedCommand, &[]);
        assert!(matches!(
            handle_fuse_increase_caliptra_min_svn(req.as_bytes(), &mut driver, &mut []),
            Err(TransportError::BufferError(_))
        ));
    }

    #[test]
    fn get_auth_challenge_requires_exact_response_length() {
        let challenge = [0x5A; fuse::AUTH_CMD_CHALLENGE_SIZE];
        let mut driver = FakeDriver {
            response: success_response(CaliptraVdmCommand::AuthorizedCommand, &challenge),
            last_request: Vec::new(),
        };
        let mut response = [0u8; core::mem::size_of::<fuse::GetAuthCmdChallengeResponse>()];
        handle_get_auth_challenge(&[], &mut driver, &mut response).unwrap();

        driver.response.push(0);
        assert!(matches!(
            handle_get_auth_challenge(&[], &mut driver, &mut response),
            Err(TransportError::InvalidMessage)
        ));
    }

    #[test]
    fn debug_unlock_req_rejects_trailing_response_bytes() {
        let req = ProdDebugUnlockReqRequest::new(1);
        let mut data = vec![0xA5; 4 + UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE + 1];
        data[..4].copy_from_slice(&21u32.to_le_bytes());
        let mut driver = FakeDriver {
            response: success_response(CaliptraVdmCommand::RequestDebugUnlock, &data),
            last_request: Vec::new(),
        };
        let mut response_buffer = [0u8; core::mem::size_of::<ProdDebugUnlockReqResponse>()];

        let err = handle_prod_debug_unlock_req(req.as_bytes(), &mut driver, &mut response_buffer)
            .expect_err("DebugUnlock response with trailing bytes must be rejected");

        assert!(matches!(err, TransportError::InvalidMessage));
        data.truncate(4 + UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE);
        driver.response = success_response(CaliptraVdmCommand::RequestDebugUnlock, &data);
        handle_prod_debug_unlock_req(req.as_bytes(), &mut driver, &mut response_buffer)
            .expect("exact-length DebugUnlock response should be accepted");
        assert_eq!(
            driver.last_request,
            [
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::RequestDebugUnlock as u8,
            ]
            .into_iter()
            .chain(req.as_bytes().iter().copied())
            .collect::<Vec<_>>()
        );

        data[..4].copy_from_slice(&20u32.to_le_bytes());
        driver.response = success_response(CaliptraVdmCommand::RequestDebugUnlock, &data);
        assert!(matches!(
            handle_prod_debug_unlock_req(req.as_bytes(), &mut driver, &mut response_buffer),
            Err(TransportError::InvalidMessage)
        ));
    }

    #[test]
    fn authorized_dot_commands_preserve_family_subcommand_and_payload() {
        let cases: [(u32, Vec<u8>, VdmCommandHandlerFn); 3] = [
            (
                MC_DOT_LOCK_CANONICAL_CMD_ID,
                DotLockRequest::default().as_bytes().to_vec(),
                handle_dot_lock,
            ),
            (
                MC_DOT_DISABLE_CANONICAL_CMD_ID,
                DotDisableRequest::default().as_bytes().to_vec(),
                handle_dot_disable,
            ),
            (
                MC_DOT_ROTATE_CANONICAL_CMD_ID,
                DotRotateRequest::default().as_bytes().to_vec(),
                handle_dot_rotate,
            ),
        ];

        for (subcommand, payload, handler) in cases {
            let mut driver = FakeDriver {
                response: success_response(CaliptraVdmCommand::AuthorizedCommand, &[]),
                last_request: Vec::new(),
            };
            let mut response_buffer = [0u8; core::mem::size_of::<DotTransitionResponse>()];

            handler(&payload, &mut driver, &mut response_buffer)
                .expect("authorized DOT command should be accepted");

            assert_eq!(
                &driver.last_request[..2],
                &[
                    CALIPTRA_VDM_COMMAND_VERSION,
                    CaliptraVdmCommand::AuthorizedCommand as u8,
                ]
            );
            assert_eq!(&driver.last_request[2..6], &DOT_FAMILY_ID.to_le_bytes());
            assert_eq!(&driver.last_request[6..10], &subcommand.to_le_bytes());
            assert_eq!(&driver.last_request[10..], payload);
            let response = DotTransitionResponse::read_from_bytes(&response_buffer).unwrap();
            assert_eq!(response.reset_required, 1);
        }
    }

    #[test]
    fn native_dot_transition_commands_preserve_subcommand_and_payload() {
        let cases: [(u32, Vec<u8>, VdmCommandHandlerFn); 3] = [
            (
                MC_DOT_UNLOCK_CANONICAL_CMD_ID,
                DotUnlockRequest::default().as_bytes().to_vec(),
                handle_dot_unlock,
            ),
            (
                MC_DOT_RECOVERY_CANONICAL_CMD_ID,
                DotRecoveryRequest::default().as_bytes().to_vec(),
                handle_dot_recovery,
            ),
            (
                MC_DOT_OVERRIDE_CANONICAL_CMD_ID,
                DotOverrideRequest::default().as_bytes().to_vec(),
                handle_dot_override,
            ),
        ];

        for (subcommand, payload, handler) in cases {
            let mut driver = FakeDriver {
                response: success_response(CaliptraVdmCommand::DeviceOwnershipTransfer, &[]),
                last_request: Vec::new(),
            };
            let mut response_buffer = [0u8; core::mem::size_of::<DotTransitionResponse>()];

            handler(&payload, &mut driver, &mut response_buffer)
                .expect("native DOT transition should be accepted");

            assert_eq!(
                &driver.last_request[..2],
                &[
                    CALIPTRA_VDM_COMMAND_VERSION,
                    CaliptraVdmCommand::DeviceOwnershipTransfer as u8,
                ]
            );
            assert_eq!(&driver.last_request[2..6], &subcommand.to_le_bytes());
            assert_eq!(&driver.last_request[6..], payload);
            let response = DotTransitionResponse::read_from_bytes(&response_buffer).unwrap();
            assert_eq!(response.reset_required, 1);
        }
    }

    #[test]
    fn dot_requests_fit_session_and_spdm_large_message_limits() {
        const SESSION_LIMIT: usize = 8 * 1024;
        const LIBSPDM_LIMIT: usize = 0x2000;
        const AUTHORIZED_ENVELOPE: usize = 2 + 4 + 4;
        const NATIVE_ENVELOPE: usize = 2 + 4;

        let largest_request = [
            core::mem::size_of::<DotLockRequest>() + AUTHORIZED_ENVELOPE,
            core::mem::size_of::<DotDisableRequest>() + AUTHORIZED_ENVELOPE,
            core::mem::size_of::<DotRotateRequest>() + AUTHORIZED_ENVELOPE,
            core::mem::size_of::<GetDotBackupBlobRequest>() + AUTHORIZED_ENVELOPE,
            core::mem::size_of::<DotUnlockRequest>() + NATIVE_ENVELOPE,
            core::mem::size_of::<DotRecoveryRequest>() + NATIVE_ENVELOPE,
            core::mem::size_of::<DotOverrideChallengeRequest>() + NATIVE_ENVELOPE,
            core::mem::size_of::<DotOverrideRequest>() + NATIVE_ENVELOPE,
        ]
        .into_iter()
        .max()
        .unwrap();
        assert!(largest_request <= SESSION_LIMIT);
        assert!(largest_request <= LIBSPDM_LIMIT);
    }

    #[test]
    fn dot_unlock_challenge_decodes_exact_length_response() {
        let expected_challenge = [0xA5; AUTH_CMD_NONCE_LEN];
        let mut driver = FakeDriver {
            response: success_response(
                CaliptraVdmCommand::DeviceOwnershipTransfer,
                &expected_challenge,
            ),
            last_request: Vec::new(),
        };
        let mut response_buffer = [0u8; core::mem::size_of::<DotChallengeResponse>()];

        handle_dot_unlock_challenge(&[], &mut driver, &mut response_buffer)
            .expect("DOT unlock challenge should be accepted");

        assert_eq!(
            driver.last_request,
            [
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::DeviceOwnershipTransfer as u8,
                MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID.to_le_bytes()[0],
                MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID.to_le_bytes()[1],
                MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID.to_le_bytes()[2],
                MC_DOT_UNLOCK_CHALLENGE_CANONICAL_CMD_ID.to_le_bytes()[3],
            ]
        );
        assert_eq!(&response_buffer[4..], &expected_challenge);

        driver.response = success_response(
            CaliptraVdmCommand::DeviceOwnershipTransfer,
            &[0; AUTH_CMD_NONCE_LEN - 1],
        );
        assert!(matches!(
            handle_dot_unlock_challenge(&[], &mut driver, &mut response_buffer),
            Err(TransportError::InvalidMessage)
        ));
    }

    #[test]
    fn dot_backup_status_and_override_challenge_use_expected_envelopes() {
        let backup_blob = [0x5A; DOT_BLOB_SIZE];
        let backup_request = GetDotBackupBlobRequest::default();
        let mut driver = FakeDriver {
            response: success_response(CaliptraVdmCommand::AuthorizedCommand, &backup_blob),
            last_request: Vec::new(),
        };
        let mut backup_response = vec![0u8; core::mem::size_of::<GetDotBackupBlobResponse>()];
        handle_get_dot_backup_blob(backup_request.as_bytes(), &mut driver, &mut backup_response)
            .unwrap();
        assert_eq!(
            driver.last_request[1],
            CaliptraVdmCommand::AuthorizedCommand as u8
        );
        assert_eq!(&driver.last_request[2..6], &DOT_FAMILY_ID.to_le_bytes());
        assert_eq!(
            &driver.last_request[6..10],
            &MC_GET_DOT_BACKUP_BLOB_CANONICAL_CMD_ID.to_le_bytes()
        );
        assert_eq!(&driver.last_request[10..], backup_request.as_bytes());
        let backup = GetDotBackupBlobResponse::read_from_bytes(&backup_response).unwrap();
        assert_eq!(backup.blob, backup_blob);

        driver.response =
            success_response(CaliptraVdmCommand::DeviceOwnershipTransfer, &[1, 1, 3, 0]);
        let mut status_response = [0u8; core::mem::size_of::<DotStatusResponse>()];
        handle_dot_status(&[], &mut driver, &mut status_response).unwrap();
        assert_eq!(
            driver.last_request[1],
            CaliptraVdmCommand::DeviceOwnershipTransfer as u8
        );
        assert_eq!(
            &driver.last_request[2..6],
            &MC_DOT_STATUS_CANONICAL_CMD_ID.to_le_bytes()
        );
        let status = DotStatusResponse::read_from_bytes(&status_response).unwrap();
        assert_eq!(status.status.enabled, 1);
        assert_eq!(status.status.locked, 1);
        assert_eq!(status.status.burned, 3);

        let challenge = [0xC3; AUTH_CMD_NONCE_LEN];
        let override_request = DotOverrideChallengeRequest::default();
        driver.response = success_response(CaliptraVdmCommand::DeviceOwnershipTransfer, &challenge);
        let mut challenge_response = [0u8; core::mem::size_of::<DotChallengeResponse>()];
        handle_dot_override_challenge(
            override_request.as_bytes(),
            &mut driver,
            &mut challenge_response,
        )
        .unwrap();
        assert_eq!(
            &driver.last_request[2..6],
            &MC_DOT_OVERRIDE_CHALLENGE_CANONICAL_CMD_ID.to_le_bytes()
        );
        assert_eq!(&driver.last_request[6..], override_request.as_bytes());
        let response = DotChallengeResponse::read_from_bytes(&challenge_response).unwrap();
        assert_eq!(response.challenge, challenge);
    }
}
