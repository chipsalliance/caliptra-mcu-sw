// Licensed under the Apache-2.0 license

use crate::measurements::common::{
    DmtfMeasurementBlockMetadata, MeasurementValueType, MeasurementsError, MeasurementsResult,
    SPDM_MEASUREMENT_MANIFEST_INDEX,
};
use crate::protocol::SHA384_HASH_SIZE;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libapi_caliptra::evidence::{Evidence, PCR_QUOTE_SIZE};
use libapi_caliptra::mailbox_api::MAX_CRYPTO_MBOX_DATA_SIZE;
use zerocopy::IntoBytes;

const MAX_MEASUREMENT_RECORD_SIZE: usize =
    PCR_QUOTE_SIZE + size_of::<DmtfMeasurementBlockMetadata>();

/// Structure to hold the Freeform manifest data
/// The measurement record consists of 1 measurement block whose value is the PCR quote from Caliptra.
/// The strucuture of the measurement record is as follows:
/// _________________________________________________________________________________________________
/// | - index: SPDM_MEASUREMENT_MANIFEST_INDEX                                                      |
/// | - MeasurementSpecification: 01h (DMTF)                                                        |
/// |           - DMTFSpecMeasurementValueType[6:0]: 04h (Freeform Manifest)                        |
/// |           - DMTFSpecMeasurementValueType[7]  : 1b  (raw bit-stream)                           |
/// | - MeasurementSize: 2 bytes (size of the PCR Quote in DMTF measurement specification format)   |
/// | - MeasurementBlock: measurement block (PCR Quote in DMTF measurement specification format)    |
/// ________________________________________________________________________________________________|
pub struct FreeformManifest {
    measurement_record: [u8; MAX_MEASUREMENT_RECORD_SIZE],
}

impl Default for FreeformManifest {
    fn default() -> Self {
        FreeformManifest {
            measurement_record: [0; MAX_MEASUREMENT_RECORD_SIZE],
        }
    }
}

#[allow(dead_code)]
impl FreeformManifest {
    pub(crate) fn total_measurement_count(&self) -> usize {
        1
    }

    pub(crate) async fn measurement_block_size(
        &mut self,
        index: u8,
        raw_bit_stream: bool,
    ) -> usize {
        if index != SPDM_MEASUREMENT_MANIFEST_INDEX {
            return 0;
        }
        if raw_bit_stream {
            return MAX_MEASUREMENT_RECORD_SIZE;
        }
        PCR_QUOTE_SIZE + size_of::<DmtfMeasurementBlockMetadata>()
    }

    pub(crate) async fn measurement_record(
        &mut self,
        _raw_bit_stream: bool,
        _offset: usize,
        _measurement_chunk: &mut [u8],
    ) -> MeasurementsResult<()> {
        todo!("Implement all measurement blocks");
    }

    pub(crate) async fn measurement_block(
        &mut self,
        index: u8,
        raw_bit_stream: bool,
        _offset: usize,
        _measurement_chunk: &mut [u8],
    ) -> MeasurementsResult<()> {
        if index != SPDM_MEASUREMENT_MANIFEST_INDEX {
            return Err(MeasurementsError::InvalidIndex);
        }
        if raw_bit_stream {
            return Err(MeasurementsError::InvalidOperation);
        }
        todo!("Implement measurement block");
    }

    pub(crate) async fn measurement_summary_hash(
        &mut self,
        _measurement_summary_hash_type: u8,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> MeasurementsResult<()> {
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
        let measurement_record = &mut self.measurement_record;
        measurement_record.fill(0);
        let metadata = DmtfMeasurementBlockMetadata::new(
            SPDM_MEASUREMENT_MANIFEST_INDEX,
            PCR_QUOTE_SIZE as u16,
            false,
            MeasurementValueType::FreeformManifest,
        )?;

        const METADATA_SIZE: usize = size_of::<DmtfMeasurementBlockMetadata>();

        measurement_record[0..METADATA_SIZE].copy_from_slice(metadata.as_bytes());

        let quote_slice = &mut measurement_record[METADATA_SIZE..METADATA_SIZE + PCR_QUOTE_SIZE];
        let quote: &mut [u8; PCR_QUOTE_SIZE] = quote_slice
            .try_into()
            .map_err(|_| MeasurementsError::InvalidBuffer)?;

        Evidence::pcr_quote(quote)
            .await
            .map_err(MeasurementsError::CaliptraApi)?;

        Ok(())
    }
}
