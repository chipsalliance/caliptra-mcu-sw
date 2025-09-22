// Licensed under the Apache-2.0 license

use crate::measurements::common::{
    DmtfMeasurementBlockMetadata, MeasurementValueType, MeasurementsError, MeasurementsResult,
    SPDM_MEASUREMENT_MANIFEST_INDEX,
};
use crate::protocol::*;
use libapi_caliptra::certificate::KEY_LABEL_SIZE;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::evidence::pcr_quote::{PcrQuote, PCR_QUOTE_BUFFER_SIZE};
use libapi_caliptra::mailbox_api::MAX_CRYPTO_MBOX_DATA_SIZE;
// use ocp_eat::token::{OcpEatCwt, OcpEatType};
use libapi_caliptra::ocp_eat_cwt::{OcpEatCwt, OcpEatType};
use zerocopy::IntoBytes;

const MAX_MEASUREMENT_RECORD_SIZE: usize =
    PCR_QUOTE_BUFFER_SIZE + size_of::<DmtfMeasurementBlockMetadata>();
const MEAS_BLOCK_METADATA_SIZE: usize = size_of::<DmtfMeasurementBlockMetadata>();

const DPE_EAT_AK_LEAF_CERT_LABEL: [u8; KEY_LABEL_SIZE] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

const EAT_DEFAULT_ISSUER: &str = "CN=Caliptra EAT DPE Attestation Key";

pub enum MeasurementValueFormat {
    PcrQuote,
    OcpCwt,
}

pub struct MeasurementManifest {
    meas_value_format: MeasurementValueFormat,
    spdm_version: Option<SpdmVersion>,
    nonce: Option<[u8; NONCE_LEN]>,
    asym_algo: Option<AsymAlgo>,
    measurement_record: [u8; MAX_MEASUREMENT_RECORD_SIZE],
    data_size: usize,
    refresh_record: bool,
}

impl Default for MeasurementManifest {
    fn default() -> Self {
        MeasurementManifest {
            meas_value_format: MeasurementValueFormat::OcpCwt,
            spdm_version: None,
            nonce: None,
            asym_algo: None,
            measurement_record: [0; MAX_MEASUREMENT_RECORD_SIZE],
            data_size: 0,
            refresh_record: true,
        }
    }
}

impl MeasurementManifest {
    pub(crate) fn set_spdm_version(&mut self, version: SpdmVersion) {
        self.spdm_version = Some(version);
    }

    pub(crate) fn set_asym_algo(&mut self, asym_algo: AsymAlgo) {
        self.asym_algo = Some(asym_algo);
    }

    pub(crate) fn set_nonce(&mut self, nonce: [u8; NONCE_LEN]) {
        self.nonce = Some(nonce);
        self.refresh_record = true;
    }

    pub(crate) fn total_measurement_count(&self) -> usize {
        1
    }

    pub(crate) async fn measurement_block_size(
        &mut self,
        index: u8,
        _raw_bit_stream: bool,
    ) -> MeasurementsResult<usize> {
        if index == SPDM_MEASUREMENT_MANIFEST_INDEX || index == 0xFF {
            if self.refresh_record || self.data_size == 0 {
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
        if index == SPDM_MEASUREMENT_MANIFEST_INDEX || index == 0xFF {
            if self.refresh_record || self.data_size == 0 {
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
        self.refresh_measurement_record().await?;

        let meas_rec_len = self.data_size;

        let mut offset = 0;
        let mut hash_ctx = HashContext::new();

        while offset < meas_rec_len {
            let chunk_size = MAX_CRYPTO_MBOX_DATA_SIZE.min(meas_rec_len - offset);

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
        match self.meas_value_format {
            MeasurementValueFormat::PcrQuote => self.refresh_pcr_quote_record().await,

            MeasurementValueFormat::OcpCwt => self.refresh_ocp_cwt_record().await,
        }
    }

    async fn refresh_pcr_quote_record(&mut self) -> MeasurementsResult<()> {
        let asym_algo = self
            .asym_algo
            .ok_or(MeasurementsError::MissingParam("AsymAlgo"))?;
        let with_pqc_sig = asym_algo != AsymAlgo::EccP384;
        let measurement_record = &mut self.measurement_record;
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
            [MEAS_BLOCK_METADATA_SIZE..MEAS_BLOCK_METADATA_SIZE + PCR_QUOTE_BUFFER_SIZE];

        let copied_len = PcrQuote::pcr_quote(quote_slice, with_pqc_sig)
            .await
            .map_err(MeasurementsError::CaliptraApi)?;
        if copied_len != measurement_value_size {
            return Err(MeasurementsError::MeasurementSizeMismatch);
        }

        self.data_size = MEAS_BLOCK_METADATA_SIZE + measurement_value_size;
        self.refresh_record = false;

        Ok(())
    }

    async fn refresh_ocp_cwt_record(&mut self) -> MeasurementsResult<()> {
        let nonce = self.nonce.unwrap_or_default();
        let asym_algo = self
            .asym_algo
            .ok_or(MeasurementsError::MissingParam("AsymAlgo"))?;
        let spdm_version = self
            .spdm_version
            .ok_or(MeasurementsError::MissingParam("SpdmVersion"))?;
        let meas_val_type = if spdm_version < SpdmVersion::V13 {
            MeasurementValueType::FreeformManifest
        } else {
            MeasurementValueType::StructuredManifest
        };

        let ocp_cwt_slice = &mut self.measurement_record[MEAS_BLOCK_METADATA_SIZE..];

        let ocp_cwt = OcpEatCwt::new(
            OcpEatType::EatClaims,
            asym_algo,
            &nonce,
            &DPE_EAT_AK_LEAF_CERT_LABEL,
            EAT_DEFAULT_ISSUER,
        )
        .map_err(MeasurementsError::CaliptraApi)?;

        let ocp_cwt_size = ocp_cwt
            .generate(ocp_cwt_slice)
            .await
            .map_err(MeasurementsError::CaliptraApi)?;
        let metadata = DmtfMeasurementBlockMetadata::new(
            SPDM_MEASUREMENT_MANIFEST_INDEX,
            ocp_cwt_size as u16,
            false,
            meas_val_type,
        )?;
        self.measurement_record[0..MEAS_BLOCK_METADATA_SIZE].copy_from_slice(metadata.as_bytes());
        self.data_size = MEAS_BLOCK_METADATA_SIZE + ocp_cwt_size;

        Ok(())
    }
}
