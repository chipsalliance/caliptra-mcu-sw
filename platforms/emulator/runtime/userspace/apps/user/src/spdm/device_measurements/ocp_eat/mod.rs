// Licensed under the Apache-2.0 license

extern crate alloc;

pub mod claims;

pub use claims::init_target_env_claims;

use alloc::boxed::Box;
use async_trait::async_trait;
use libapi_caliptra::certificate::KEY_LABEL_SIZE;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::signed_eat::SignedEat;
use spdm_lib::measurements::{
    MeasurementValueInfo, MeasurementsError, MeasurementsResult, SpdmMeasurementValue,
};

const DPE_EAT_AK_LEAF_CERT_LABEL: [u8; KEY_LABEL_SIZE] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

pub const NUM_OCP_EAT_MEASUREMENTS: usize = 1;

pub fn create_manifest_with_ocp_eat() -> (
    OcpEatManifest,
    [MeasurementValueInfo; NUM_OCP_EAT_MEASUREMENTS],
) {
    let manifest = OcpEatManifest::new();

    let meas_info = MeasurementValueInfo::structured_manifest(
        false, // raw_bit_stream
        true,  // include_tcb_measurements
    );

    (manifest, [meas_info])
}

pub struct OcpEatManifest;

impl OcpEatManifest {
    pub fn new() -> Self {
        OcpEatManifest {}
    }
}

#[async_trait]
impl SpdmMeasurementValue for OcpEatManifest {
    async fn get_measurement_value(
        &mut self,
        _index: u8,
        nonce: &[u8],
        asym_algo: AsymAlgo,
        measurement: &mut [u8],
    ) -> MeasurementsResult<usize> {
        let mut claims_buf = [0u8; 1024];
        let payload_size = claims::generate_claims(&mut claims_buf, nonce).await?;

        if payload_size > measurement.len() {
            return Err(MeasurementsError::BufferTooSmall);
        }

        let signed_eat = SignedEat::new(asym_algo, &DPE_EAT_AK_LEAF_CERT_LABEL)
            .map_err(MeasurementsError::CaliptraApi)?;

        signed_eat
            .generate(&claims_buf[..payload_size], measurement)
            .await
            .map_err(MeasurementsError::CaliptraApi)
    }
}
