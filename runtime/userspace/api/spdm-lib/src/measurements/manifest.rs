// Licensed under the Apache-2.0 license

use crate::measurements::common::{
    DmtfMeasurementBlockMetadata, MeasurementValueType, MeasurementsError, MeasurementsResult,
    SPDM_MEASUREMENT_MANIFEST_INDEX,
};
use crate::protocol::*;
// use libapi_caliptra::certificate::KEY_LABEL_SIZE;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::mailbox_api::MAX_CRYPTO_MBOX_DATA_SIZE;
use zerocopy::IntoBytes;

pub const MAX_MEASUREMENT_RECORD_SIZE: usize = 4096;
pub const MEAS_BLOCK_METADATA_SIZE: usize = size_of::<DmtfMeasurementBlockMetadata>();

// pub enum MeasurementValueFormat {
//     PcrQuote,
//     OcpCwt,
// }

pub struct MeasurementManifest {
    // meas_value_format: MeasurementValueFormat,
    // spdm_version: Option<SpdmVersion>,
    pub(crate) nonce: Option<[u8; NONCE_LEN]>,
    pub(crate) asym_algo: Option<AsymAlgo>,
    pub(crate) measurement_record: [u8; MAX_MEASUREMENT_RECORD_SIZE],
    pub(crate) data_size: usize,
    // refresh_record: bool,
}

impl Default for MeasurementManifest {
    fn default() -> Self {
        MeasurementManifest {
            // meas_value_format: MeasurementValueFormat::OcpCwt,
            // spdm_version: None,
            nonce: None,
            asym_algo: None,
            measurement_record: [0; MAX_MEASUREMENT_RECORD_SIZE],
            data_size: 0,
            // refresh_record: true,
        }
    }
}

impl MeasurementManifest {
    // pub(crate) fn set_spdm_version(&mut self, version: SpdmVersion) {
    //     self.spdm_version = Some(version);
    // }

    pub(crate) fn set_asym_algo(&mut self, asym_algo: AsymAlgo) {
        self.asym_algo = Some(asym_algo);
    }

    pub(crate) fn set_nonce(&mut self, nonce: [u8; NONCE_LEN]) {
        self.nonce = Some(nonce);
        // self.refresh_record = true;
    }

    pub(crate) fn total_measurement_count(&self) -> usize {
        1
    }

    pub(crate) fn size(&self) -> usize {
        self.data_size
    }

    pub(crate) async fn measurement_block(
        &mut self,
        offset: usize,
        measurement_chunk: &mut [u8],
    ) -> MeasurementsResult<usize> {
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
    }

    pub(crate) async fn measurement_summary_hash(
        &mut self,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> MeasurementsResult<()> {
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
}
