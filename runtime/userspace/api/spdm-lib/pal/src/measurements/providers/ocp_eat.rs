// Licensed under the Apache-2.0 license

//! OCP EAT measurement provider for spdm-lib.
//!
//! Measurement API owns component inventory, readout, lineage filtering, and
//! concise-evidence encoding. The shared attestation-evidence API wraps those
//! bytes in OCP EAT claims and signs the payload with the selected AK.

use crate::alloc::BitmapAllocator;
use crate::measurements::MeasurementProvider;
use caliptra_mcu_attestation_evidence::{
    encode_signed_ocp_eat, ocp_eat::NONCE_LEN, SIGNED_OCP_EAT_MAX_SIZE,
    SIGNED_OCP_EAT_WORKSPACE_SIZE,
};
use caliptra_mcu_spdm_traits::{MeasurementInfo, SPDM_NONCE_LEN};
use mcu_caliptra_api_lite::DPE_LABEL_LEN;
use mcu_error::McuResult;

/// Single measurement entry: index 0xFD, StructuredManifest.
const OCP_EAT_MEAS_INFO: [MeasurementInfo; 1] = [MeasurementInfo {
    index: 0xFD,
    value_size: SIGNED_OCP_EAT_MAX_SIZE as u16,
    value_type: 10, // StructuredManifest
    is_raw: true,
    is_tcb: true,
}];
const OCP_EAT_MEAS_INDEX: u8 = 0xFD;
const _: () = assert!(SPDM_NONCE_LEN == NONCE_LEN);
static ZERO_NONCE: [u8; SPDM_NONCE_LEN] = [0u8; SPDM_NONCE_LEN];

/// Measurement provider that returns signed OCP EAT evidence.
pub struct OcpEatMeasurementProvider {
    key_label: [u8; DPE_LABEL_LEN],
}

impl OcpEatMeasurementProvider {
    pub fn new(key_label: [u8; DPE_LABEL_LEN]) -> Self {
        Self { key_label }
    }
}

impl MeasurementProvider for OcpEatMeasurementProvider {
    const SCRATCH_SIZE: usize = SIGNED_OCP_EAT_WORKSPACE_SIZE;

    fn measurement_info(&self) -> &[MeasurementInfo] {
        &OCP_EAT_MEAS_INFO
    }

    async fn get_measurement_value(
        &self,
        index: u8,
        nonce: Option<&[u8; SPDM_NONCE_LEN]>,
        out: &mut [u8],
        scratch: &mut [u8],
        alloc: &BitmapAllocator,
    ) -> McuResult<usize> {
        if index != OCP_EAT_MEAS_INDEX {
            return Err(mcu_error::codes::INTERNAL_BUG);
        }

        // The EAT token is always signed. When SPDM did not provide a requester
        // nonce, bind a zero nonce in the EAT payload and omit the outer SPDM
        // measurement-response signature.
        let eat_nonce = nonce.unwrap_or(&ZERO_NONCE);
        encode_signed_ocp_eat(alloc, &self.key_label, eat_nonce, scratch, out).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_info_describes_static_ocp_eat_block() {
        let provider = OcpEatMeasurementProvider::new([0u8; DPE_LABEL_LEN]);
        let info = provider.measurement_info();

        assert_eq!(info.len(), 1);
        assert_eq!(info[0].index, OCP_EAT_MEAS_INDEX);
        assert_eq!(info[0].value_size, SIGNED_OCP_EAT_MAX_SIZE as u16);
        assert_eq!(info[0].value_type, 10);
        assert!(info[0].is_raw);
        assert!(info[0].is_tcb);
    }
}
