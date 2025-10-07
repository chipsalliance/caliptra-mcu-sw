// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::evidence::pcr_quote::PcrQuote;
use spdm_lib::measurements::{
    MeasurementValueInfo, MeasurementsError, MeasurementsResult, SpdmMeasurementValue,
};

pub const NUM_PCR_QUOTE_MEASUREMENTS: usize = 1;

pub fn create_manifest_with_pcr_quote() -> (
    PcrQuoteManifest,
    [MeasurementValueInfo; NUM_PCR_QUOTE_MEASUREMENTS],
) {
    let manifest = PcrQuoteManifest::new();

    let meas_info = MeasurementValueInfo::freeform_manifest(
        false, // raw_bit_stream
        true,  // include_tcb_measurements
    );

    (manifest, [meas_info])
}

pub struct PcrQuoteManifest;

impl PcrQuoteManifest {
    pub fn new() -> Self {
        PcrQuoteManifest {}
    }
}

#[async_trait]
impl SpdmMeasurementValue for PcrQuoteManifest {
    async fn get_measurement_value(
        &mut self,
        _index: u8,
        nonce: &[u8],
        asym_algo: AsymAlgo,
        measurement: &mut [u8],
    ) -> MeasurementsResult<usize> {
        let with_pqc_sig = asym_algo != AsymAlgo::EccP384;
        let measurement_value_size = PcrQuote::len(with_pqc_sig);
        if measurement.len() < measurement_value_size {
            return Err(MeasurementsError::BufferTooSmall);
        }
        let copied_len = PcrQuote::pcr_quote(Some(nonce), measurement, with_pqc_sig)
            .await
            .map_err(MeasurementsError::CaliptraApi)?;

        Ok(copied_len)
    }
}
