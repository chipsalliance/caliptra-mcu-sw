use crate::measurements::common::{
    DmtfMeasurementBlockMetadata, MeasurementValueType, MeasurementsError, MeasurementsResult,
    SPDM_MEASUREMENT_MANIFEST_INDEX,
};
use crate::measurements::manifest::*;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::evidence::pcr_quote::PcrQuote;
use zerocopy::IntoBytes;

pub struct PcrQuoteManifest {
    meas_manifest: MeasurementManifest,
    refresh_record: bool,
}

impl Default for PcrQuoteManifest {
    fn default() -> Self {
        PcrQuoteManifest {
            meas_manifest: MeasurementManifest::default(),
            refresh_record: true,
        }
    }
}

impl PcrQuoteManifest {
    pub(crate) fn set_nonce(&mut self, nonce: [u8; 32]) {
        self.meas_manifest.set_nonce(nonce);
        self.refresh_record = true;
    }

    pub(crate) fn set_asym_algo(&mut self, asym_algo: AsymAlgo) {
        self.meas_manifest.set_asym_algo(asym_algo);
    }

    pub(crate) fn total_measurement_count(&self) -> usize {
        self.meas_manifest.total_measurement_count()
    }

    pub(crate) async fn measurement_block_size(
        &mut self,
        index: u8,
        raw_bit_stream: bool,
    ) -> MeasurementsResult<usize> {
        if index == SPDM_MEASUREMENT_MANIFEST_INDEX || index == 0xFF {
            if self.refresh_record || self.meas_manifest.size() == 0 {
                self.refresh_measurement_record().await?;
            }
            Ok(self.meas_manifest.size())
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
        if index == SPDM_MEASUREMENT_MANIFEST_INDEX || index == 0xFF {
            if self.refresh_record || self.meas_manifest.size() == 0 {
                self.refresh_measurement_record().await?;
            }

            self.meas_manifest
                .measurement_block(offset, measurement_chunk)
                .await
        } else {
            Err(MeasurementsError::InvalidIndex)
        }
    }

    pub(crate) async fn measurement_summary_hash(
        &mut self,
        _measurement_summary_hash_type: u8,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> MeasurementsResult<()> {
        self.refresh_measurement_record().await?;
        self.meas_manifest.measurement_summary_hash(hash).await
    }

    async fn refresh_measurement_record(&mut self) -> MeasurementsResult<()> {
        let asym_algo = self
            .meas_manifest
            .asym_algo
            .ok_or(MeasurementsError::MissingParam("AsymAlgo"))?;
        let with_pqc_sig = asym_algo != AsymAlgo::EccP384;
        let measurement_record = &mut self.meas_manifest.measurement_record;
        let measurement_value_size = PcrQuote::len(with_pqc_sig);
        measurement_record.fill(0);
        let metadata = DmtfMeasurementBlockMetadata::new(
            SPDM_MEASUREMENT_MANIFEST_INDEX,
            measurement_value_size as u16,
            false,
            MeasurementValueType::FreeformManifest,
        )?;

        measurement_record[0..MEAS_BLOCK_METADATA_SIZE].copy_from_slice(metadata.as_bytes());

        let quote_slice = &mut measurement_record
            [MEAS_BLOCK_METADATA_SIZE..MEAS_BLOCK_METADATA_SIZE + measurement_value_size];

        let copied_len = PcrQuote::pcr_quote(quote_slice, with_pqc_sig)
            .await
            .map_err(MeasurementsError::CaliptraApi)?;
        if copied_len != measurement_value_size {
            return Err(MeasurementsError::MeasurementSizeMismatch);
        }

        self.meas_manifest.data_size = MEAS_BLOCK_METADATA_SIZE + measurement_value_size;
        self.refresh_record = false;

        Ok(())
    }
}
