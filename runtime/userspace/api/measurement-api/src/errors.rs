// Licensed under the Apache-2.0 license

//! Measurement API error codes within [`mcu_error::domain::ATTESTATION`].
//!
//! Subdomain and code allocations are owned by this crate. The
//! [`MeasurementApiError`] enum discriminants are the `code` field of the
//! packed [`McuErrorCode`]; `domain` and `subdomain` are named constants so
//! the codes stay within the append-only registry.

use mcu_error::{domain, McuErrorCode};

use crate::attestation_manifest::AttestationManifestError;

/// Boot-initialization error subdomain under [`domain::ATTESTATION`].
pub const SUBDOMAIN_BOOT_INIT: u8 = 0x01;

/// Measurement API boot/initialization error categories.
///
/// Each discriminant is the low-16-bit `code` packed into a
/// [`McuErrorCode`] as `(ATTESTATION, SUBDOMAIN_BOOT_INIT, code)`.
#[repr(u16)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MeasurementApiError {
    /// The attestation manifest failed to parse or validate.
    InvalidManifest = 0x0001,
    /// Computing the attestation policy digest failed.
    DigestFailed = 0x0002,
    /// A DPE Handle Storage or Software PCR Storage operation failed.
    StoreFailed = 0x0003,
    /// A DPE command failed before producing a usable result.
    DpeCommandFailed = 0x0004,
    /// MCU-side DPE Handle Storage state was missing or semantically invalid.
    InvalidDpeHandleStoreState = 0x0005,
    /// Attestation is disabled because measurement state is in an error state.
    AttestationDisabled = 0x0006,
    /// The runtime SoC image load-list topology is inconsistent with policy.
    InvalidSocImageLoadList = 0x0007,
    /// A caller referenced a firmware identifier not present in policy.
    UnknownFwId = 0x0008,
    /// Caliptra image authorization failed.
    ImageAuthorizationFailed = 0x0009,
    /// Extending Caliptra PCR31 failed.
    PcrExtendFailed = 0x000a,
    /// Measurement state already exists for the requested firmware identifier.
    DuplicateMeasurementRecord = 0x000b,
}

/// Convenience alias for a Measurement API operation result. `T` defaults to
/// `()` so `MeasurementApiResult` reads as "succeeds or fails with a
/// [`MeasurementApiError`]".
pub type MeasurementApiResult<T = ()> = Result<T, MeasurementApiError>;

impl From<MeasurementApiError> for McuErrorCode {
    fn from(e: MeasurementApiError) -> Self {
        McuErrorCode::new(domain::ATTESTATION, SUBDOMAIN_BOOT_INIT, e as u16)
    }
}

impl From<AttestationManifestError> for MeasurementApiError {
    fn from(_: AttestationManifestError) -> Self {
        MeasurementApiError::InvalidManifest
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn error_codes_pack_expected_fields() {
        for (err, code) in [
            (MeasurementApiError::InvalidManifest, 0x0001u16),
            (MeasurementApiError::DigestFailed, 0x0002),
            (MeasurementApiError::StoreFailed, 0x0003),
            (MeasurementApiError::DpeCommandFailed, 0x0004),
            (MeasurementApiError::InvalidDpeHandleStoreState, 0x0005),
            (MeasurementApiError::AttestationDisabled, 0x0006),
            (MeasurementApiError::InvalidSocImageLoadList, 0x0007),
            (MeasurementApiError::UnknownFwId, 0x0008),
            (MeasurementApiError::ImageAuthorizationFailed, 0x0009),
            (MeasurementApiError::PcrExtendFailed, 0x000a),
            (MeasurementApiError::DuplicateMeasurementRecord, 0x000b),
        ] {
            let mcu: McuErrorCode = err.into();
            assert_eq!(mcu.domain(), domain::ATTESTATION);
            assert_eq!(mcu.subdomain(), SUBDOMAIN_BOOT_INIT);
            assert_eq!(mcu.code(), code);
        }
    }

    #[test]
    fn manifest_error_folds_to_invalid_manifest() {
        assert_eq!(
            MeasurementApiError::from(AttestationManifestError::InvalidMarker),
            MeasurementApiError::InvalidManifest
        );
    }
}
