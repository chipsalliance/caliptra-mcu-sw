// Licensed under the Apache-2.0 license

use crate::measurements::common::{
    DmtfMeasurementBlockMetadata, MeasurementValueType, MeasurementsError, MeasurementsResult,
    SPDM_MEASUREMENT_MANIFEST_INDEX,
};
use crate::protocol::*;
use arrayvec::ArrayVec;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::mailbox_api::MAX_CRYPTO_MBOX_DATA_SIZE;
use zerocopy::IntoBytes;

// // Max protected header length in the COSE_Sign1 structure
// const MAX_PROTECTED_HEADER_LEN: usize = 128;
// // Max unprotected header length in the COSE_Sign1 structure
// const MAX_UNPROTECTED_HEADER_LEN: usize = 8192;
// // Maximum size of the payload in the COSE_Sign1 structure
// const MAX_PAYLOAD_LEN: usize = 4096;
// // Maximum size of the COSE_Sign1 structure with signature with MLDSA87
// const MAX_SIGNATURE_LEN: usize = 96;

const MAX_MEASUREMENT_RECORD_SIZE: usize = 4096;

/// Structure to hold the OCP CWT Structured manifest data
/// The measurement record consists of 1 measurement block whose value is OCP CWT.
/// The strucuture of the measurement record is as follows:
/// ____________________________________________________________________________________________________
/// | - index: SPDM_MEASUREMENT_MANIFEST_INDEX                                                          |
/// | - MeasurementSpecification: 01h (DMTF)                                                            |
/// |           - DMTFSpecMeasurementValueType[6:0]: 04h (Freeform Manifest for SPDMv1.2)/              |
/// |                                                0Ah (Structured Manifest for > SPDMv1.2)           |
/// |           - DMTFSpecMeasurementValueType[7]  : 1b  (raw bit-stream)                               |
/// | - MeasurementSize: 2 bytes (size of the signed OCP CWT in DMTF meas spec format)                  |
/// | - MeasurementBlock: measurement block (signed OCP CWT in DMTF meas spec format)                   |
/// |___________________________________________________________________________________________________|

pub struct OcpCwt {
    spdm_version: Option<SpdmVersion>,
    asym_algo: Option<AsymAlgo>,
    measurement_record: [u8; MAX_MEASUREMENT_RECORD_SIZE],
    data_size: usize,
    nonce: Option<[u8; NONCE_LEN]>,
    // signed_cwt: SignedEat,
}

impl Default for OcpCwt {
    fn default() -> Self {
        OcpCwt {
            spdm_version: None,
            asym_algo: None,
            measurement_record: [0; MAX_MEASUREMENT_RECORD_SIZE],
            data_size: 0,
            nonce: None,
        }
    }
}

impl OcpCwt {
    pub(crate) fn set_nonce(&mut self, nonce: [u8; 32]) {
        self.nonce = Some(nonce);
    }

    pub(crate) fn set_spdm_version(&mut self, version: SpdmVersion) {
        self.spdm_version = Some(version);
    }

    pub(crate) fn set_asym_algo(&mut self, asym_algo: AsymAlgo) {
        self.asym_algo = Some(asym_algo);
    }

    pub(crate) fn total_measurement_count(&self) -> usize {
        1
    }

    pub(crate) async fn measurement_block_size(
        &mut self,
        index: u8,
        _raw_bit_stream: bool,
    ) -> MeasurementsResult<usize> {
        let asym_algo = self.asym_algo.ok_or(MeasurementsError::MissingParam("AsymAlgo"))?;
        if index == SPDM_MEASUREMENT_MANIFEST_INDEX || index == 0xFF {
            if self.data_size == 0 {
                self.refresh_measurement_record().await?;
            }
            Ok(self.data_size)
        } else {
            Err(MeasurementsError::InvalidIndex)
        }
    }

    pub(crate) async fn measurement_block(
        &mut self,
        index: u8,
        _raw_bit_stream: bool,
        offset: usize,
        measurement_chunk: &mut [u8],
    ) -> MeasurementsResult<usize> {
        let _asym_algo = self.asym_algo.ok_or(MeasurementsError::MissingParam("AsymAlgo"))?;
        if index == SPDM_MEASUREMENT_MANIFEST_INDEX || index == 0xFF {
            if self.data_size == 0 {
                self.refresh_measurement_record().await?;
            }
            if offset >= self.data_size {
                return Err(MeasurementsError::InvalidOffset);
            }

            let end = self
                .measurement_record
                .len()
                .min(offset + measurement_chunk.len());
            let chunk_size = end - offset;
            measurement_chunk[..chunk_size].copy_from_slice(&self.measurement_record[offset..end]);

            Ok(chunk_size)
        } else {
            Err(MeasurementsError::InvalidIndex)
        }
    }

    pub(crate) async fn measurement_summary_hash(
        &mut self,
        _measurement_summary_hash_type: u8,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> MeasurementsResult<()> {
        let asym_algo = self.asym_algo.ok_or(MeasurementsError::MissingParam("AsymAlgo"))?;
        self.refresh_measurement_record().await?;

        let mut offset = 0;
        let mut hash_ctx = HashContext::new();

        while offset < self.measurement_record.len() {
            let chunk_size = MAX_CRYPTO_MBOX_DATA_SIZE.min(self.measurement_record.len() - offset);

            if offset == 0 {
                hash_ctx
                    .init(
                        HashAlgoType::SHA384,
                        Some(&self.measurement_record[..chunk_size]),
                    )
                    .await
                    .map_err(MeasurementsError::CaliptraApi)?;
            } else {
                let chunk = &self.measurement_record[offset..offset + chunk_size];
                hash_ctx
                    .update(chunk)
                    .await
                    .map_err(MeasurementsError::CaliptraApi)?;
            }

            offset += chunk_size;
        }

        hash_ctx
            .finalize(hash)
            .await
            .map_err(MeasurementsError::CaliptraApi)
    }

    async fn refresh_measurement_record(&mut self) -> MeasurementsResult<()> {
        let _asym_algo = self.asym_algo.ok_or(MeasurementsError::MissingParam("AsymAlgo"))?;
        let measurement_record = &mut self.measurement_record;
        measurement_record.fill(0);
        let spdm_version = self
            .spdm_version
            .ok_or(MeasurementsError::MissingParam("SpdmVersion"))?;
        let measurement_value_type = if spdm_version < SpdmVersion::V13 {
            MeasurementValueType::FreeformManifest
        } else {
            MeasurementValueType::StructuredManifest
        };

        todo!("Implement OCP EAT measurement record refresh");

        // let metadata = DmtfMeasurementBlockMetadata::new(
        //     SPDM_MEASUREMENT_MANIFEST_INDEX,
        //     measurement_value_size as u16,
        //     false,
        //     measurement_value_type,
        // )?;

        // const METADATA_SIZE: usize = size_of::<DmtfMeasurementBlockMetadata>();

        // measurement_record[0..METADATA_SIZE].copy_from_slice(metadata.as_bytes());
    }
}
