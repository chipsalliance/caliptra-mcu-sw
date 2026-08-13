// Licensed under the Apache-2.0 license

//! Attestation command types.
//!
//! Mirrors the device-side `GET_ATTESTATION` contract defined in
//! `docs/src/caliptra_common_commands.md`. The same request/response pair is
//! carried over both the SPDM VDM transport (Caliptra VDM command `0x05`) and
//! the MCI mailbox transport (`MC_GET_ATTESTATION`, `0x4D47_4154`).

use crate::{CaliptraCommandId, CommandRequest, CommandResponse, CommonResponse};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Maximum evidence payload the host will accept for a single response.
///
/// Sized to the device's advertised large-message budget (`MAX_SPDM_MSG_SIZE`),
/// which bounds every evidence blob the device can emit. The whole response
/// struct must still fit the session's 8 KiB packet buffer, so this must not be
/// raised without raising that buffer too.
pub const MAX_ATTESTATION_DATA_SIZE: usize = 7 * 1024;

/// Length of the freshness nonce, in bytes.
pub const ATTESTATION_NONCE_LEN: usize = 32;

/// Reserved `evidence_format` value that requests the supported-format bitmap
/// instead of evidence.
pub const EVIDENCE_FORMAT_QUERY: u32 = 0;

/// Evidence format selector carried in the request and echoed in the response.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceFormat {
    /// OCP Entity Attestation Token, wrapped in a COSE_Sign1 envelope.
    OcpEat = 1,
    /// Caliptra PCR quote.
    PcrQuote = 2,
}

impl EvidenceFormat {
    /// Bit position of this format within the supported-format bitmap returned
    /// by a discovery query.
    ///
    /// Bit `n` is set when the device supports the format whose wire value is
    /// `n`, so bit 0 is never set (it is the query sentinel). This must match
    /// `EvidenceFormat::bit` in `caliptra-mcu-common-commands`.
    pub const fn bit(self) -> u32 {
        1u32 << (self as u32)
    }

    /// Human-readable name, for test and CLI output.
    pub const fn name(self) -> &'static str {
        match self {
            EvidenceFormat::OcpEat => "OcpEat",
            EvidenceFormat::PcrQuote => "PcrQuote",
        }
    }

    /// All formats the host knows how to ask for.
    pub const ALL: &'static [EvidenceFormat] = &[EvidenceFormat::OcpEat, EvidenceFormat::PcrQuote];
}

impl TryFrom<u32> for EvidenceFormat {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EvidenceFormat::OcpEat),
            2 => Ok(EvidenceFormat::PcrQuote),
            _ => Err(()),
        }
    }
}

/// Signing algorithm selector carried in the request.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceAlgorithm {
    /// ECDSA over NIST P-384 with SHA-384.
    EccP384 = 1,
    /// ML-DSA-87.
    Mldsa87 = 2,
}

impl EvidenceAlgorithm {
    /// Human-readable name, for test and CLI output.
    pub const fn name(self) -> &'static str {
        match self {
            EvidenceAlgorithm::EccP384 => "EccP384",
            EvidenceAlgorithm::Mldsa87 => "Mldsa87",
        }
    }
}

impl TryFrom<u32> for EvidenceAlgorithm {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EvidenceAlgorithm::EccP384),
            2 => Ok(EvidenceAlgorithm::Mldsa87),
            _ => Err(()),
        }
    }
}

/// GET_ATTESTATION request.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetAttestationRequest {
    /// Evidence format (0=query supported formats, 1=OCP EAT, 2=PCR quote)
    pub evidence_format: u32,
    /// Signing algorithm (0x0001=ECC384, 0x0002=MLDSA87)
    pub algorithm: u32,
    /// Freshness nonce, bound into the signed evidence
    pub nonce: [u8; ATTESTATION_NONCE_LEN],
}

/// GET_ATTESTATION response.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct GetAttestationResponse {
    pub common: CommonResponse,
    /// Format actually produced; echoes the request, or 0 for a discovery query
    pub evidence_format: u32,
    /// Length of the evidence payload in bytes
    pub data_len: u32,
    /// Evidence payload, or the supported-format bitmap for a discovery query
    pub data: [u8; MAX_ATTESTATION_DATA_SIZE],
}

impl CommandRequest for GetAttestationRequest {
    type Response = GetAttestationResponse;
    const COMMAND_ID: CaliptraCommandId = CaliptraCommandId::GetAttestation;
}

impl CommandResponse for GetAttestationResponse {}

impl GetAttestationRequest {
    /// Builds a request for a specific format/algorithm pair.
    pub fn new(format: EvidenceFormat, algorithm: EvidenceAlgorithm, nonce: &[u8; 32]) -> Self {
        Self {
            evidence_format: format as u32,
            algorithm: algorithm as u32,
            nonce: *nonce,
        }
    }

    /// Builds a discovery query, which returns the supported-format bitmap.
    ///
    /// The algorithm field is not interpreted for a query but must still be a
    /// recognized value, so the device can reject malformed requests uniformly.
    pub fn query() -> Self {
        Self {
            evidence_format: EVIDENCE_FORMAT_QUERY,
            algorithm: EvidenceAlgorithm::EccP384 as u32,
            nonce: [0u8; ATTESTATION_NONCE_LEN],
        }
    }
}

/// Errors from attestation payload validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationValidationError {
    /// Evidence payload is empty (data_len == 0)
    Empty,
    /// Evidence payload exceeds the maximum the host can hold
    TooLarge(usize),
    /// Device echoed a format other than the one requested
    FormatMismatch { requested: u32, returned: u32 },
    /// A discovery query returned something other than a 4-byte bitmap
    MalformedBitmap(usize),
}

impl core::fmt::Display for AttestationValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AttestationValidationError::Empty => write!(f, "evidence payload is empty"),
            AttestationValidationError::TooLarge(len) => {
                write!(f, "evidence data_len {} exceeds maximum", len)
            }
            AttestationValidationError::FormatMismatch {
                requested,
                returned,
            } => write!(
                f,
                "device echoed evidence_format {:#06x}, expected {:#06x}",
                returned, requested
            ),
            AttestationValidationError::MalformedBitmap(len) => {
                write!(f, "discovery query returned {} bytes, expected 4", len)
            }
        }
    }
}

impl GetAttestationResponse {
    /// Returns the evidence payload as a byte slice.
    pub fn evidence_bytes(&self) -> &[u8] {
        let len = (self.data_len as usize).min(MAX_ATTESTATION_DATA_SIZE);
        &self.data[..len]
    }

    /// Validates an evidence response against the format that was requested,
    /// returning the evidence byte length on success.
    pub fn validate_evidence_payload(
        &self,
        requested: EvidenceFormat,
    ) -> Result<usize, AttestationValidationError> {
        let len = self.data_len as usize;
        if len == 0 {
            return Err(AttestationValidationError::Empty);
        }
        if len > MAX_ATTESTATION_DATA_SIZE {
            return Err(AttestationValidationError::TooLarge(len));
        }
        if self.evidence_format != requested as u32 {
            return Err(AttestationValidationError::FormatMismatch {
                requested: requested as u32,
                returned: self.evidence_format,
            });
        }
        Ok(len)
    }

    /// Decodes the supported-format bitmap from a discovery-query response.
    pub fn supported_formats(&self) -> Result<u32, AttestationValidationError> {
        if self.evidence_format != EVIDENCE_FORMAT_QUERY {
            return Err(AttestationValidationError::FormatMismatch {
                requested: EVIDENCE_FORMAT_QUERY,
                returned: self.evidence_format,
            });
        }
        let len = self.data_len as usize;
        if len != 4 {
            return Err(AttestationValidationError::MalformedBitmap(len));
        }
        Ok(u32::from_le_bytes([
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
        ]))
    }
}

/// Returns the formats advertised by a supported-format bitmap.
pub fn formats_from_bitmap(bitmap: u32) -> impl Iterator<Item = EvidenceFormat> {
    EvidenceFormat::ALL
        .iter()
        .copied()
        .filter(move |f| bitmap & f.bit() != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout_matches_device_contract() {
        // 4 (format) + 4 (algorithm) + 32 (nonce)
        assert_eq!(core::mem::size_of::<GetAttestationRequest>(), 40);
    }

    #[test]
    fn response_fits_session_packet_buffer() {
        // session::MAX_COMMAND_PACKET_SIZE is 8 KiB and the whole struct is
        // memcpy'd into it by the transport layer.
        assert!(core::mem::size_of::<GetAttestationResponse>() <= 8 * 1024);
    }

    #[test]
    fn bitmap_round_trips() {
        // Literals, not the encoder: bit n corresponds to wire value n, and must
        // match the device's `EvidenceFormat::bit`.
        assert_eq!(EvidenceFormat::OcpEat.bit(), 0x2);
        assert_eq!(EvidenceFormat::PcrQuote.bit(), 0x4);

        let bitmap = EvidenceFormat::OcpEat.bit() | EvidenceFormat::PcrQuote.bit();
        let mut both = formats_from_bitmap(bitmap);
        assert_eq!(both.next(), Some(EvidenceFormat::OcpEat));
        assert_eq!(both.next(), Some(EvidenceFormat::PcrQuote));
        assert_eq!(both.next(), None);

        let mut only_eat = formats_from_bitmap(EvidenceFormat::OcpEat.bit());
        assert_eq!(only_eat.next(), Some(EvidenceFormat::OcpEat));
        assert_eq!(only_eat.next(), None);
    }

    #[test]
    fn format_mismatch_is_rejected() {
        let mut resp = GetAttestationResponse {
            common: CommonResponse { fips_status: 0 },
            evidence_format: EvidenceFormat::PcrQuote as u32,
            data_len: 8,
            data: [0u8; MAX_ATTESTATION_DATA_SIZE],
        };
        assert_eq!(
            resp.validate_evidence_payload(EvidenceFormat::OcpEat),
            Err(AttestationValidationError::FormatMismatch {
                requested: EvidenceFormat::OcpEat as u32,
                returned: EvidenceFormat::PcrQuote as u32,
            })
        );

        resp.evidence_format = EvidenceFormat::OcpEat as u32;
        assert_eq!(
            resp.validate_evidence_payload(EvidenceFormat::OcpEat),
            Ok(8)
        );
    }

    #[test]
    fn empty_evidence_is_rejected() {
        let resp = GetAttestationResponse {
            common: CommonResponse { fips_status: 0 },
            evidence_format: EvidenceFormat::OcpEat as u32,
            data_len: 0,
            data: [0u8; MAX_ATTESTATION_DATA_SIZE],
        };
        assert_eq!(
            resp.validate_evidence_payload(EvidenceFormat::OcpEat),
            Err(AttestationValidationError::Empty)
        );
    }

    #[test]
    fn query_response_decodes_bitmap() {
        let mut data = [0u8; MAX_ATTESTATION_DATA_SIZE];
        data[..4].copy_from_slice(&EvidenceFormat::PcrQuote.bit().to_le_bytes());
        let resp = GetAttestationResponse {
            common: CommonResponse { fips_status: 0 },
            evidence_format: EVIDENCE_FORMAT_QUERY,
            data_len: 4,
            data,
        };
        assert_eq!(resp.supported_formats(), Ok(EvidenceFormat::PcrQuote.bit()));
    }
}
