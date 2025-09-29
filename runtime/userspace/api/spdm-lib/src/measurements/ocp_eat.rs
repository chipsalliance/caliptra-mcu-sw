use crate::measurements::common::{
    DmtfMeasurementBlockMetadata, MeasurementValueType, MeasurementsError, MeasurementsResult,
    SPDM_MEASUREMENT_MANIFEST_INDEX,
};
use crate::measurements::manifest::*;
use crate::protocol::*;
use libapi_caliptra::certificate::KEY_LABEL_SIZE;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::evidence::ocp_eat_claims::OcpEatCwt;
use ocp_eat::eat_encoder::EvTriplesMap;
use zerocopy::IntoBytes;

const DPE_EAT_AK_LEAF_CERT_LABEL: [u8; KEY_LABEL_SIZE] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

const EAT_DEFAULT_ISSUER: &str = "CN=Caliptra EAT DPE Attestation Key";

pub struct OcpEatManifest<'a> {
    meas_manifest: MeasurementManifest,
    spdm_version: Option<SpdmVersion>,
    ev_triples_map: &'a mut EvTriplesMap<'a>,
    refresh_record: bool,
}

impl<'a> OcpEatManifest<'a> {
    pub fn new(ev_triples_map: &'a mut EvTriplesMap<'a>) -> Self {
        OcpEatManifest {
            meas_manifest: MeasurementManifest::default(),
            spdm_version: None,
            ev_triples_map,
            refresh_record: true,
        }
    }

    pub(crate) fn set_spdm_version(&mut self, version: SpdmVersion) {
        self.spdm_version = Some(version);
    }

    pub(crate) fn set_asym_algo(&mut self, asym_algo: AsymAlgo) {
        self.meas_manifest.set_asym_algo(asym_algo);
    }

    pub(crate) fn set_nonce(&mut self, nonce: [u8; NONCE_LEN]) {
        self.meas_manifest.set_nonce(nonce);
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
        let nonce = self.meas_manifest.nonce.unwrap_or([0u8; NONCE_LEN]);
        let asym_algo = self
            .meas_manifest
            .asym_algo
            .ok_or(MeasurementsError::MissingParam("AsymAlgo"))?;
        let spdm_version = self
            .spdm_version
            .ok_or(MeasurementsError::MissingParam("SpdmVersion"))?;

        let ev_triples_map = &mut self.ev_triples_map;

        let meas_val_type = if spdm_version < SpdmVersion::V13 {
            MeasurementValueType::FreeformManifest
        } else {
            MeasurementValueType::StructuredManifest
        };

        let ocp_cwt_slice = &mut self.meas_manifest.measurement_record[MEAS_BLOCK_METADATA_SIZE..];

        let mut ocp_cwt = OcpEatCwt::new(
            asym_algo,
            &nonce,
            &DPE_EAT_AK_LEAF_CERT_LABEL,
            EAT_DEFAULT_ISSUER,
        )
        .map_err(MeasurementsError::CaliptraApi)?;

        let ocp_cwt_size = ocp_cwt
            .generate_evidence_claims(ev_triples_map, ocp_cwt_slice)
            .await
            .map_err(MeasurementsError::CaliptraApi)?;
        let metadata = DmtfMeasurementBlockMetadata::new(
            SPDM_MEASUREMENT_MANIFEST_INDEX,
            ocp_cwt_size as u16,
            false,
            meas_val_type,
        )?;
        self.meas_manifest.measurement_record[0..MEAS_BLOCK_METADATA_SIZE]
            .copy_from_slice(metadata.as_bytes());
        self.meas_manifest.data_size = MEAS_BLOCK_METADATA_SIZE + ocp_cwt_size;
        self.refresh_record = false;

        Ok(())
    }
}
