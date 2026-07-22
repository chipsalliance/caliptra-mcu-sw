// Licensed under the Apache-2.0 license

//! Caliptra API-lite error codes within [`mcu_error::domain::CALIPTRA_API`].
//!
//! Subdomain and code allocations are owned by this crate.

use mcu_error::{domain, McuErrorCode};

/// Image-loading errors under [`domain::CALIPTRA_API`].
pub const SUBDOMAIN_IMAGE_LOADING: u8 = 0x01;

/// Firmware-update errors under [`domain::CALIPTRA_API`].
pub const SUBDOMAIN_FIRMWARE_UPDATE: u8 = 0x02;

pub mod image_loading {
    use super::{domain, McuErrorCode, SUBDOMAIN_IMAGE_LOADING};

    const fn code(code: u16) -> McuErrorCode {
        McuErrorCode::new(domain::CALIPTRA_API, SUBDOMAIN_IMAGE_LOADING, code)
    }

    /// The caller supplied more firmware IDs than the Caliptra command supports.
    pub const FW_ID_COUNT_TOO_LARGE: McuErrorCode = code(0x0001);
    /// Building an image-loading mailbox request failed.
    pub const REQUEST_BUILD_FAILED: McuErrorCode = code(0x0002);
    /// GET_IMAGE_INFO failed in Caliptra mailbox execution.
    pub const GET_IMAGE_INFO_FAILED: McuErrorCode = code(0x0003);
    /// GET_IMAGE_INFO returned fewer bytes than the fixed response layout requires.
    pub const IMAGE_INFO_RESPONSE_TOO_SHORT: McuErrorCode = code(0x0004);
    /// A mailbox command response did not contain the common response header.
    pub const MAILBOX_RESPONSE_TOO_SHORT: McuErrorCode = code(0x0005);
    /// The Auth Manifest described by flash metadata is larger than supported.
    pub const AUTH_MANIFEST_TOO_LARGE: McuErrorCode = code(0x0006);
    /// VERIFY_AUTH_MANIFEST failed in Caliptra mailbox execution.
    pub const AUTH_MANIFEST_VERIFICATION_FAILED: McuErrorCode = code(0x0007);
    /// ACTIVATE_FIRMWARE failed in Caliptra mailbox execution.
    pub const FIRMWARE_ACTIVATION_FAILED: McuErrorCode = code(0x0008);
    /// The flash image header could not be parsed.
    pub const INVALID_FLASH_HEADER: McuErrorCode = code(0x0009);
    /// A flash image TOC entry could not be parsed.
    pub const INVALID_IMAGE_HEADER: McuErrorCode = code(0x000a);
    /// The requested image ID was not found in the flash or PLDM image TOC.
    pub const IMAGE_NOT_FOUND: McuErrorCode = code(0x000b);
    /// Image offset or address arithmetic overflowed.
    pub const IMAGE_OFFSET_OVERFLOW: McuErrorCode = code(0x000c);
    /// The DMA transfer implementation reported a zero maximum transfer size.
    pub const DMA_TRANSFER_SIZE_ZERO: McuErrorCode = code(0x000d);
    /// PLDM image loading observed an unexpected state transition.
    pub const PLDM_UNEXPECTED_STATE: McuErrorCode = code(0x000e);
    /// The flash header advertised more images than the PLDM image-loader supports.
    pub const PLDM_IMAGE_COUNT_TOO_LARGE: McuErrorCode = code(0x000f);
    /// PLDM streaming boot was started without firmware-device descriptors.
    pub const PLDM_DESCRIPTORS_EMPTY: McuErrorCode = code(0x0010);
    /// Spawning the PLDM service task failed.
    pub const PLDM_TASK_SPAWN_FAILED: McuErrorCode = code(0x0011);
    /// The PLDM service failed to reach the initialized state.
    pub const PLDM_SERVICE_START_FAILED: McuErrorCode = code(0x0012);
    /// Reading streamed Auth Manifest bytes from flash failed.
    pub const AUTH_MANIFEST_STREAM_FAILED: McuErrorCode = code(0x0013);
}

pub mod firmware_update {
    use super::{domain, McuErrorCode, SUBDOMAIN_FIRMWARE_UPDATE};

    const fn code(code: u16) -> McuErrorCode {
        McuErrorCode::new(domain::CALIPTRA_API, SUBDOMAIN_FIRMWARE_UPDATE, code)
    }

    /// Firmware-update manifest validation failed.
    pub const MANIFEST_VALIDATION_FAILED: McuErrorCode = code(0x0001);
    /// Firmware-update image loading or staging failed.
    pub const IMAGE_STAGING_FAILED: McuErrorCode = code(0x0002);
    /// Firmware-update verification failed.
    pub const VERIFICATION_FAILED: McuErrorCode = code(0x0003);
    /// Firmware-update activation failed.
    pub const ACTIVATION_FAILED: McuErrorCode = code(0x0004);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_loading_errors_pack_expected_fields() {
        for (err, code) in [
            (image_loading::FW_ID_COUNT_TOO_LARGE, 0x0001),
            (image_loading::REQUEST_BUILD_FAILED, 0x0002),
            (image_loading::GET_IMAGE_INFO_FAILED, 0x0003),
            (image_loading::IMAGE_INFO_RESPONSE_TOO_SHORT, 0x0004),
            (image_loading::MAILBOX_RESPONSE_TOO_SHORT, 0x0005),
            (image_loading::AUTH_MANIFEST_TOO_LARGE, 0x0006),
            (image_loading::AUTH_MANIFEST_VERIFICATION_FAILED, 0x0007),
            (image_loading::FIRMWARE_ACTIVATION_FAILED, 0x0008),
            (image_loading::INVALID_FLASH_HEADER, 0x0009),
            (image_loading::INVALID_IMAGE_HEADER, 0x000a),
            (image_loading::IMAGE_NOT_FOUND, 0x000b),
            (image_loading::IMAGE_OFFSET_OVERFLOW, 0x000c),
            (image_loading::DMA_TRANSFER_SIZE_ZERO, 0x000d),
            (image_loading::PLDM_UNEXPECTED_STATE, 0x000e),
            (image_loading::PLDM_IMAGE_COUNT_TOO_LARGE, 0x000f),
            (image_loading::PLDM_DESCRIPTORS_EMPTY, 0x0010),
            (image_loading::PLDM_TASK_SPAWN_FAILED, 0x0011),
            (image_loading::PLDM_SERVICE_START_FAILED, 0x0012),
            (image_loading::AUTH_MANIFEST_STREAM_FAILED, 0x0013),
        ] {
            assert_eq!(err.domain(), domain::CALIPTRA_API);
            assert_eq!(err.subdomain(), SUBDOMAIN_IMAGE_LOADING);
            assert_eq!(err.code(), code);
        }
    }

    #[test]
    fn firmware_update_errors_pack_expected_fields() {
        for (err, code) in [
            (firmware_update::MANIFEST_VALIDATION_FAILED, 0x0001),
            (firmware_update::IMAGE_STAGING_FAILED, 0x0002),
            (firmware_update::VERIFICATION_FAILED, 0x0003),
            (firmware_update::ACTIVATION_FAILED, 0x0004),
        ] {
            assert_eq!(err.domain(), domain::CALIPTRA_API);
            assert_eq!(err.subdomain(), SUBDOMAIN_FIRMWARE_UPDATE);
            assert_eq!(err.code(), code);
        }
    }
}
