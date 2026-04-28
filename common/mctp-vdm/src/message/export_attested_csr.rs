// Licensed under the Apache-2.0 license

//! Export Attested CSR command (0x0C)
//!
//! Exports an attested Certificate Signing Request (CSR) for a specified device key.

use crate::codec::{VdmCodec, VdmCodecError};
use crate::error::VdmError;
use crate::protocol::{VdmCommand, VdmMsgHeader};
use core::convert::TryFrom;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Re-exported from `caliptra_api::mailbox::MAX_ATTESTED_CSR_RESP_DATA_SIZE`.
pub use caliptra_api::mailbox::MAX_ATTESTED_CSR_RESP_DATA_SIZE as MAX_ATTESTED_CSR_SIZE;

/// Device Key ID values for Export Attested CSR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceKeyId {
    /// LDevID key.
    LDevId = 0x0001,
    /// FMC Alias key.
    FmcAlias = 0x0002,
    /// RT Alias key.
    RtAlias = 0x0003,
}

impl TryFrom<u32> for DeviceKeyId {
    type Error = VdmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(DeviceKeyId::LDevId),
            0x0002 => Ok(DeviceKeyId::FmcAlias),
            0x0003 => Ok(DeviceKeyId::RtAlias),
            _ => Err(VdmError::InvalidData),
        }
    }
}

/// Asymmetric algorithm values for Export Attested CSR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AsymAlgorithm {
    /// ECC P-384.
    Ecc384 = 0x0001,
    /// ML-DSA-87 (Dilithium).
    MlDsa87 = 0x0002,
}

impl TryFrom<u32> for AsymAlgorithm {
    type Error = VdmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(AsymAlgorithm::Ecc384),
            0x0002 => Ok(AsymAlgorithm::MlDsa87),
            _ => Err(VdmError::InvalidData),
        }
    }
}

/// Export Attested CSR Request.
///
/// Request Payload:
/// - Bytes 0:3 - device_key_id (u32): Identifier of the device key to export CSR for
///   - 0x0001 = LDevID
///   - 0x0002 = FMC Alias
///   - 0x0003 = RT Alias
/// - Bytes 4:7 - algorithm (u32): Asymmetric algorithm
///   - 0x0001 = ECC384
///   - 0x0002 = MLDSA87
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ExportAttestedCsrRequest {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Device key identifier.
    pub device_key_id: u32,
    /// Asymmetric algorithm.
    pub algorithm: u32,
}

impl ExportAttestedCsrRequest {
    /// Create a new Export Attested CSR request.
    pub fn new(device_key_id: u32, algorithm: u32) -> Self {
        ExportAttestedCsrRequest {
            hdr: VdmMsgHeader::new_request(VdmCommand::ExportAttestedCsr.into()),
            device_key_id,
            algorithm,
        }
    }
}

impl Default for ExportAttestedCsrRequest {
    fn default() -> Self {
        Self::new(DeviceKeyId::LDevId as u32, AsymAlgorithm::Ecc384 as u32)
    }
}

/// Export Attested CSR Response (fixed header part).
///
/// Response Payload:
/// - Bytes 0:3 - completion_code (u32): Command completion status
/// - Bytes 4:7 - data_size (u32): Length in bytes of the attested CSR data
/// - Bytes 8:N - data (u8[data_size]): Attested CSR data blob
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ExportAttestedCsrResponseHeader {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Command completion status.
    pub completion_code: u32,
    /// Size of the attested CSR data in bytes.
    pub data_size: u32,
}

impl ExportAttestedCsrResponseHeader {
    /// Create a new Export Attested CSR response header.
    pub fn new(completion_code: u32, data_size: u32) -> Self {
        ExportAttestedCsrResponseHeader {
            hdr: VdmMsgHeader::new_response(VdmCommand::ExportAttestedCsr.into()),
            completion_code,
            data_size,
        }
    }
}

impl Default for ExportAttestedCsrResponseHeader {
    fn default() -> Self {
        ExportAttestedCsrResponseHeader {
            hdr: VdmMsgHeader::new_response(VdmCommand::ExportAttestedCsr.into()),
            completion_code: 0,
            data_size: 0,
        }
    }
}

/// Export Attested CSR Response with variable-length data.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportAttestedCsrResponse {
    /// Response header.
    pub header: ExportAttestedCsrResponseHeader,
    /// Attested CSR data buffer.
    pub data: [u8; MAX_ATTESTED_CSR_SIZE],
}

impl ExportAttestedCsrResponse {
    /// Create a new Export Attested CSR response.
    pub fn new(completion_code: u32, data: &[u8]) -> Self {
        let data_size = data.len().min(MAX_ATTESTED_CSR_SIZE);
        let mut response_data = [0u8; MAX_ATTESTED_CSR_SIZE];
        response_data[..data_size].copy_from_slice(&data[..data_size]);

        ExportAttestedCsrResponse {
            header: ExportAttestedCsrResponseHeader::new(completion_code, data_size as u32),
            data: response_data,
        }
    }

    /// Get the actual data size.
    pub fn data_size(&self) -> usize {
        self.header.data_size as usize
    }

    /// Get a slice of the actual data.
    pub fn data(&self) -> &[u8] {
        let size = self.data_size().min(MAX_ATTESTED_CSR_SIZE);
        &self.data[..size]
    }
}

impl Default for ExportAttestedCsrResponse {
    fn default() -> Self {
        ExportAttestedCsrResponse {
            header: ExportAttestedCsrResponseHeader::default(),
            data: [0u8; MAX_ATTESTED_CSR_SIZE],
        }
    }
}

impl VdmCodec for ExportAttestedCsrResponse {
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, VdmCodecError> {
        let header_size = core::mem::size_of::<ExportAttestedCsrResponseHeader>();
        let data_size = self.data_size();
        let total_size = header_size + data_size;

        if buffer.len() < total_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        // Encode header
        self.header.encode(buffer)?;

        // Copy data
        buffer[header_size..total_size].copy_from_slice(&self.data[..data_size]);

        Ok(total_size)
    }

    fn decode(buffer: &[u8]) -> Result<Self, VdmCodecError> {
        let header_size = core::mem::size_of::<ExportAttestedCsrResponseHeader>();

        if buffer.len() < header_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        let header = ExportAttestedCsrResponseHeader::decode(buffer)?;
        let data_size = (header.data_size as usize).min(MAX_ATTESTED_CSR_SIZE);

        if buffer.len() < header_size + data_size {
            return Err(VdmCodecError::BufferTooShort);
        }

        let mut data = [0u8; MAX_ATTESTED_CSR_SIZE];
        data[..data_size].copy_from_slice(&buffer[header_size..header_size + data_size]);

        Ok(ExportAttestedCsrResponse { header, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{VdmCompletionCode, VDM_MSG_HEADER_LEN};

    #[test]
    fn test_export_attested_csr_request() {
        let req =
            ExportAttestedCsrRequest::new(DeviceKeyId::LDevId as u32, AsymAlgorithm::Ecc384 as u32);
        assert!(req.hdr.is_request());
        let command_code = req.hdr.command_code;
        let device_key_id = req.device_key_id;
        let algorithm = req.algorithm;
        assert_eq!(command_code, VdmCommand::ExportAttestedCsr as u8);
        assert_eq!(device_key_id, 0x0001);
        assert_eq!(algorithm, 0x0001);

        let mut buffer = [0u8; 64];
        let size = req.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN + 8);

        let decoded = ExportAttestedCsrRequest::decode(&buffer).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_export_attested_csr_response() {
        let data = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02];
        let resp = ExportAttestedCsrResponse::new(VdmCompletionCode::Success as u32, &data);
        assert!(resp.header.hdr.is_response());

        let header_size = core::mem::size_of::<ExportAttestedCsrResponseHeader>();
        let mut buffer = [0u8; MAX_ATTESTED_CSR_SIZE + 64];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, header_size + data.len());

        let decoded = ExportAttestedCsrResponse::decode(&buffer[..size]).unwrap();
        assert_eq!(decoded.data_size(), data.len());
        assert_eq!(decoded.data(), &data);
    }

    #[test]
    fn test_export_attested_csr_response_empty() {
        let resp = ExportAttestedCsrResponse::new(VdmCompletionCode::GeneralError as u32, &[]);
        assert_eq!(resp.data_size(), 0);
        assert_eq!(resp.data(), &[]);
    }

    #[test]
    fn test_device_key_id_values() {
        assert_eq!(DeviceKeyId::LDevId as u32, 0x0001);
        assert_eq!(DeviceKeyId::FmcAlias as u32, 0x0002);
        assert_eq!(DeviceKeyId::RtAlias as u32, 0x0003);
    }

    #[test]
    fn test_asym_algorithm_values() {
        assert_eq!(AsymAlgorithm::Ecc384 as u32, 0x0001);
        assert_eq!(AsymAlgorithm::MlDsa87 as u32, 0x0002);
    }

    #[test]
    fn test_device_key_id_try_from() {
        assert_eq!(DeviceKeyId::try_from(0x0001), Ok(DeviceKeyId::LDevId));
        assert_eq!(DeviceKeyId::try_from(0x0002), Ok(DeviceKeyId::FmcAlias));
        assert_eq!(DeviceKeyId::try_from(0x0003), Ok(DeviceKeyId::RtAlias));
        assert!(DeviceKeyId::try_from(0x0000).is_err());
        assert!(DeviceKeyId::try_from(0x0004).is_err());
        assert!(DeviceKeyId::try_from(0xFFFF).is_err());
    }

    #[test]
    fn test_asym_algorithm_try_from() {
        assert_eq!(AsymAlgorithm::try_from(0x0001), Ok(AsymAlgorithm::Ecc384));
        assert_eq!(AsymAlgorithm::try_from(0x0002), Ok(AsymAlgorithm::MlDsa87));
        assert!(AsymAlgorithm::try_from(0x0000).is_err());
        assert!(AsymAlgorithm::try_from(0x0003).is_err());
        assert!(AsymAlgorithm::try_from(0xFFFF).is_err());
    }
}
