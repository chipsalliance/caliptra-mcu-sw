// Licensed under the Apache-2.0 license

//! [`SpdmPalMeasurements`] implementation for [`McuSpdmPal`].
//!
//! Measurement data is supplied by the platform via a generic
//! [`MeasurementProvider`] type parameter on [`McuSpdmPal`].

use crate::alloc::BitmapAllocator;
use caliptra_mcu_spdm_traits::{MeasurementInfo, SpdmPalMeasurements, SPDM_NONCE_LEN};
use mcu_error::McuResult;

use crate::pal::McuSpdmPal;

pub mod providers;

/// Platform-specific measurement data provider.
///
/// Integrators implement this trait to supply device-specific
/// measurement values (firmware digests, HW config, device mode, etc.).
///
/// Methods are async to support providers that require mailbox
/// calls (e.g., OCP EAT signed evidence via DPE).
#[allow(async_fn_in_trait)]
pub trait MeasurementProvider: Sync + 'static {
    /// Scratch buffer size (bytes) the provider needs for intermediate
    /// work during [`Self::get_measurement_value`]. The PAL bridge
    /// allocates this from the bitmap scratch pool and passes it in.
    /// Providers that need no scratch set this to `0`.
    const SCRATCH_SIZE: usize;

    /// Available measurement entries.
    fn measurement_info(&self) -> &[MeasurementInfo];

    /// Retrieve measurement value for `index` into `out`.
    /// `nonce` is the SPDM requester nonce (32 bytes) when signature
    /// was requested, or `None` for unsigned requests.
    /// `scratch` is a caller-provided working buffer of at least
    /// [`Self::SCRATCH_SIZE`] bytes (empty slice when `SCRATCH_SIZE == 0`).
    /// `alloc` is the bitmap allocator for transient DPE/SHA mailbox
    /// buffers — providers that perform signing or hashing use this
    /// instead of stack-allocating large arrays.
    /// Returns bytes written.
    async fn get_measurement_value(
        &self,
        index: u8,
        nonce: Option<&[u8; SPDM_NONCE_LEN]>,
        out: &mut [u8],
        scratch: &mut [u8],
        alloc: &BitmapAllocator,
    ) -> McuResult<usize>;
}

impl<M: MeasurementProvider> SpdmPalMeasurements for McuSpdmPal<M> {
    fn measurement_info(&self) -> &[MeasurementInfo] {
        self.meas_provider.measurement_info()
    }

    async fn get_measurement_value(
        &self,
        _io: &Self::Io<'_>,
        index: u8,
        nonce: Option<&[u8; SPDM_NONCE_LEN]>,
        out: &mut [u8],
    ) -> McuResult<usize> {
        if M::SCRATCH_SIZE > 0 {
            let mut scratch = self
                .allocator
                .alloc_bytes(M::SCRATCH_SIZE)
                .map_err(|_| mcu_error::codes::INTERNAL_BUG)?;
            scratch.fill(0);
            self.meas_provider
                .get_measurement_value(index, nonce, out, &mut scratch, self.allocator)
                .await
        } else {
            self.meas_provider
                .get_measurement_value(index, nonce, out, &mut [], self.allocator)
                .await
        }
    }
}
