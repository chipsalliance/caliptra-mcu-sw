// Licensed under the Apache-2.0 license

//! Measurement provider trait for SPDM-Lite.
//!
//! Platform integrators implement [`SpdmPalMeasurements`] to supply
//! measurement data (firmware digests, configuration hashes, device mode, etc.)
//! to the GET_MEASUREMENTS handler.

use mcu_error::McuResult;

/// Nonce length from SPDM spec (32 bytes).
pub const SPDM_NONCE_LEN: usize = 32;

/// Information about a single measurement block.
#[derive(Clone, Copy, Debug)]
pub struct MeasurementInfo {
    /// Measurement index (1..=0xFE).
    pub index: u8,
    /// DMTF measurement value type (DSP0274 Table 55):
    /// 0=ImmutableROM, 1=MutableFW, 2=HwConfig, 3=FwConfig,
    /// 4=FreeformManifest, 5=DeviceMode, 6=MutFwVersion,
    /// 7=MutFwSecurityVersion, 8=HashExtended, 9=Informational,
    /// 10=StructuredManifest.
    pub value_type: u8,
    /// Whether this measurement value is already a digest (false) or
    /// raw bitstream (true).
    pub is_raw: bool,
}

/// Platform measurement provider trait.
///
/// The responder calls these methods to enumerate and retrieve
/// measurement data. The implementation is expected to be
/// zero-allocation — measurement values are written directly into
/// caller-provided buffers.
#[allow(async_fn_in_trait)]
pub trait SpdmPalMeasurements: crate::SpdmPalIoTransport {
    /// Returns the list of available measurement entries.
    /// The returned slice lifetime is tied to `&self`.
    fn measurement_info(&self) -> &[MeasurementInfo];

    /// Retrieve the measurement value for `index` into `out`.
    ///
    /// `nonce` is the SPDM requester nonce when signature was requested,
    /// or `None` for unsigned GET_MEASUREMENTS.
    ///
    /// Returns the number of bytes written.
    /// If `index` is not found, returns an error.
    async fn get_measurement_value(
        &self,
        io: &Self::Io<'_>,
        index: u8,
        nonce: Option<&[u8; SPDM_NONCE_LEN]>,
        out: &mut [u8],
    ) -> McuResult<usize>;
}
