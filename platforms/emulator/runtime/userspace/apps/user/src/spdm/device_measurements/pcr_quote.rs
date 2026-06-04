// Licensed under the Apache-2.0 license

//! PCR Quote measurement provider for spdm-lite test builds.
//!
//! This mirrors the non-lite PCR quote measurement form without depending on
//! `caliptra-api`: the provider exposes one raw DMTF freeform manifest at
//! index 0xFD and obtains the quote through `caliptra-api-lite`.

use mcu_caliptra_api_lite::{pcr_quote_ecc384, PCR_QUOTE_ECC384_LEN};
use mcu_error::McuResult;
use mcu_spdm_lite_pal::measurements::MeasurementProvider;
use mcu_spdm_lite_pal::BitmapAllocator;
use mcu_spdm_lite_traits::{MeasurementInfo, SPDM_NONCE_LEN};

const PCR_QUOTE_MEAS_INFO: [MeasurementInfo; 1] = [MeasurementInfo {
    index: 0xFD,
    value_size: PCR_QUOTE_ECC384_LEN as u16,
    value_type: 4, // FreeformManifest
    is_raw: true,
    is_tcb: true,
}];

pub struct PcrQuoteMeasurementProvider;

impl PcrQuoteMeasurementProvider {
    pub const fn new() -> Self {
        Self
    }
}

impl MeasurementProvider for PcrQuoteMeasurementProvider {
    const SCRATCH_SIZE: usize = 0;

    fn measurement_info(&self) -> &[MeasurementInfo] {
        &PCR_QUOTE_MEAS_INFO
    }

    async fn get_measurement_value(
        &self,
        _index: u8,
        nonce: Option<&[u8; SPDM_NONCE_LEN]>,
        out: &mut [u8],
        _scratch: &mut [u8],
        alloc: &BitmapAllocator,
    ) -> McuResult<usize> {
        pcr_quote_ecc384(alloc, nonce, out).await
    }
}
