// Licensed under the Apache-2.0 license

//! Attestation commands for mailbox transport
//!
//! Wire codec for `MC_GET_ATTESTATION` (0x4D47_4154, "MGAT"). The mailbox
//! response carries the echoed evidence format inside the variable-size data
//! region, so `data_len` from the mailbox header counts the 4-byte format field
//! in addition to the evidence itself.

use super::checksum::calc_checksum;
use super::command_traits::*;
use caliptra_mcu_core_util_host_command_types::attestation::{
    GetAttestationRequest, GetAttestationResponse, ATTESTATION_NONCE_LEN, MAX_ATTESTATION_DATA_SIZE,
};
use caliptra_mcu_core_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub use super::command_traits::{process_command, process_command_with_metadata};

// ============================================================================
// MC_GET_ATTESTATION Command (0x4D47_4154 - "MGAT")
// ============================================================================

/// Size of the mailbox response header preceding the data region:
/// `chksum(4) | fips_status(4) | data_len(4)`.
const MBOX_RESP_HEADER_LEN: usize = 12;

/// Size of the echoed `evidence_format` field, which is part of the data region
/// and therefore counted by `data_len`.
const EVIDENCE_FORMAT_LEN: usize = 4;

/// External command: GetAttestation request
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetAttestationRequest {
    /// Checksum over input data
    pub chksum: u32,
    /// Evidence format (0=query supported formats, 1=OCP EAT, 2=PCR quote)
    pub evidence_format: u32,
    /// Signing algorithm (0x0001=ECC384, 0x0002=MLDSA87)
    pub algorithm: u32,
    /// 32-byte nonce for freshness
    pub nonce: [u8; ATTESTATION_NONCE_LEN],
}

/// External command: GetAttestation response
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdGetAttestationResponse {
    /// Checksum field
    pub chksum: u32,
    /// FIPS approved or an error
    pub fips_status: u32,
    /// Length of the data region: `evidence_format` plus the evidence bytes
    pub data_len: u32,
    /// Format actually produced; echoes the request, or 0 for a discovery query
    pub evidence_format: u32,
    /// Evidence payload, or the supported-format bitmap for a discovery query
    pub evidence: [u8; MAX_ATTESTATION_DATA_SIZE],
}

impl FromInternalRequest<GetAttestationRequest> for ExtCmdGetAttestationRequest {
    fn from_internal(internal: &GetAttestationRequest, command_code: u32) -> Self {
        let chksum = calc_checksum(command_code, internal.as_bytes());
        Self {
            chksum,
            evidence_format: internal.evidence_format,
            algorithm: internal.algorithm,
            nonce: internal.nonce,
        }
    }
}

impl ToInternalResponse<GetAttestationResponse> for ExtCmdGetAttestationResponse {
    fn to_internal(&self) -> GetAttestationResponse {
        let mut data = [0u8; MAX_ATTESTATION_DATA_SIZE];
        // `data_len` covers the evidence_format field too; the internal type
        // reports only the evidence length.
        let evidence_len = (self.data_len as usize)
            .saturating_sub(EVIDENCE_FORMAT_LEN)
            .min(MAX_ATTESTATION_DATA_SIZE);
        data[..evidence_len].copy_from_slice(&self.evidence[..evidence_len]);

        GetAttestationResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            evidence_format: self.evidence_format,
            data_len: evidence_len as u32,
            data,
        }
    }
}

impl VariableSizeBytes for ExtCmdGetAttestationRequest {}

impl VariableSizeBytes for ExtCmdGetAttestationResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        if bytes.len() < MBOX_RESP_HEADER_LEN + EVIDENCE_FORMAT_LEN {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let evidence_format = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        let data_len_usize = data_len as usize;
        // The data region must at least hold the echoed format field, and the
        // evidence it claims must actually be present in the frame.
        if !(EVIDENCE_FORMAT_LEN..=EVIDENCE_FORMAT_LEN + MAX_ATTESTATION_DATA_SIZE)
            .contains(&data_len_usize)
            || bytes.len() < MBOX_RESP_HEADER_LEN + data_len_usize
        {
            return Err(crate::TransportError::InvalidMessage);
        }

        let evidence_len = data_len_usize - EVIDENCE_FORMAT_LEN;
        let evidence_start = MBOX_RESP_HEADER_LEN + EVIDENCE_FORMAT_LEN;

        let mut evidence = [0u8; MAX_ATTESTATION_DATA_SIZE];
        evidence[..evidence_len]
            .copy_from_slice(&bytes[evidence_start..evidence_start + evidence_len]);

        Ok(ExtCmdGetAttestationResponse {
            chksum,
            fips_status,
            data_len,
            evidence_format,
            evidence,
        })
    }

    fn to_bytes_variable(&self, buffer: &mut [u8]) -> usize {
        let evidence_len = (self.data_len as usize)
            .saturating_sub(EVIDENCE_FORMAT_LEN)
            .min(MAX_ATTESTATION_DATA_SIZE);
        let total_size = MBOX_RESP_HEADER_LEN + EVIDENCE_FORMAT_LEN + evidence_len;

        if buffer.len() < total_size {
            return 0;
        }

        buffer[0..4].copy_from_slice(&self.chksum.to_le_bytes());
        buffer[4..8].copy_from_slice(&self.fips_status.to_le_bytes());
        buffer[8..12].copy_from_slice(&self.data_len.to_le_bytes());
        buffer[12..16].copy_from_slice(&self.evidence_format.to_le_bytes());
        buffer[16..16 + evidence_len].copy_from_slice(&self.evidence[..evidence_len]);

        total_size
    }
}

// ============================================================================
// Command Metadata Definition
// ============================================================================

use crate::define_command;

define_command!(
    GetAttestationCmd,
    0x4D47_4154, // MC_GET_ATTESTATION - "MGAT"
    GetAttestationRequest,
    GetAttestationResponse,
    ExtCmdGetAttestationRequest,
    ExtCmdGetAttestationResponse
);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn frame(evidence_format: u32, evidence: &[u8]) -> Vec<u8> {
        let data_len = (EVIDENCE_FORMAT_LEN + evidence.len()) as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // chksum
        buf.extend_from_slice(&0u32.to_le_bytes()); // fips_status
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&evidence_format.to_le_bytes());
        buf.extend_from_slice(evidence);
        buf
    }

    #[test]
    fn data_len_covers_the_echoed_format_field() {
        let evidence = [0xABu8; 64];
        let bytes = frame(2, &evidence);
        let ext = ExtCmdGetAttestationResponse::from_bytes_variable(&bytes).unwrap();
        assert_eq!(ext.data_len as usize, EVIDENCE_FORMAT_LEN + evidence.len());

        let internal = ext.to_internal();
        assert_eq!(internal.evidence_format, 2);
        assert_eq!(internal.data_len as usize, evidence.len());
        assert_eq!(internal.evidence_bytes(), &evidence[..]);
    }

    #[test]
    fn truncated_frame_is_rejected() {
        let mut bytes = frame(1, &[0x11u8; 32]);
        bytes.truncate(bytes.len() - 1);
        assert!(ExtCmdGetAttestationResponse::from_bytes_variable(&bytes).is_err());
    }

    #[test]
    fn data_len_smaller_than_format_field_is_rejected() {
        let mut bytes = frame(1, &[]);
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(ExtCmdGetAttestationResponse::from_bytes_variable(&bytes).is_err());
    }

    #[test]
    fn query_frame_carries_only_the_bitmap() {
        let bitmap = 0x3u32;
        let bytes = frame(0, &bitmap.to_le_bytes());
        let internal = ExtCmdGetAttestationResponse::from_bytes_variable(&bytes)
            .unwrap()
            .to_internal();
        assert_eq!(internal.supported_formats(), Ok(bitmap));
    }

    #[test]
    fn round_trips_through_to_bytes_variable() {
        let evidence = [0x5Au8; 128];
        let bytes = frame(1, &evidence);
        let ext = ExtCmdGetAttestationResponse::from_bytes_variable(&bytes).unwrap();

        let mut out = vec![0u8; bytes.len()];
        let written = ext.to_bytes_variable(&mut out);
        assert_eq!(written, bytes.len());
        assert_eq!(out, bytes);
    }
}
