// Licensed under the Apache-2.0 license

//! PCR Quote measurement provider for spdm-lib test builds.
//!
//! This mirrors the non-lite PCR quote measurement form without depending on
//! `caliptra-api`: the provider exposes one raw DMTF freeform manifest at
//! index 0xFD and obtains the quote through `caliptra-api-lite`.

use crate::alloc::BitmapAllocator;
use crate::measurements::MeasurementProvider;
use caliptra_mcu_attestation_evidence::pcr_quote::{
    encode_pcr_quote, PcrQuoteAlgorithm, PCR_QUOTE_MAX_SIZE,
};
use caliptra_mcu_spdm_traits::{MeasurementInfo, SPDM_NONCE_LEN};
use mcu_error::McuResult;

const PCR_QUOTE_MEAS_INFO: [MeasurementInfo; 1] = [MeasurementInfo {
    index: 0xFD,
    value_size: PCR_QUOTE_MAX_SIZE as u16,
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

impl Default for PcrQuoteMeasurementProvider {
    fn default() -> Self {
        Self::new()
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
        encode_pcr_quote(alloc, PcrQuoteAlgorithm::Ecc384, nonce, out).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_info_describes_static_pcr_quote_block() {
        let provider = PcrQuoteMeasurementProvider::new();
        let info = provider.measurement_info();

        assert_eq!(info.len(), 1);
        assert_eq!(info[0].index, 0xFD);
        assert_eq!(info[0].value_size, PCR_QUOTE_MAX_SIZE as u16);
        assert_eq!(info[0].value_type, 4);
        assert!(info[0].is_raw);
        assert!(info[0].is_tcb);
    }
}
