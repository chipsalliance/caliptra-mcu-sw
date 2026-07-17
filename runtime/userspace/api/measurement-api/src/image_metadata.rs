// Licensed under the Apache-2.0 license

//! Metadata passed to Measurement API for MCU-managed image measurement flows.

use mcu_caliptra_api_lite::ImageHashSource;

/// SHA-384 digest size used for SoC image measurements.
pub const IMAGE_MEASUREMENT_DIGEST_SIZE: usize = 48;

/// Measurement operation that produced this image metadata.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MeasurementOperation {
    /// Boot-time SoC image load.
    InitialLoad = 1,
    /// Hitless SoC component update requested by firmware update logic.
    ComponentUpdate = 2,
}

/// Control flags associated with image metadata.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ImageMetadataFlags(u32);

impl ImageMetadataFlags {
    /// No metadata flags.
    pub const EMPTY: Self = Self(0);

    /// Return the raw flag bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Compact image metadata consumed by Measurement API.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ImageMetadata {
    /// Operation that produced this metadata.
    pub operation: MeasurementOperation,
    /// Source used for Caliptra image authorization.
    pub source: ImageHashSource,
    /// Image size in bytes.
    pub image_size: u32,
    /// SHA-384 image measurement digest from `GET_IMAGE_INFO`.
    pub measurement: [u8; IMAGE_MEASUREMENT_DIGEST_SIZE],
    /// Security version number associated with the image.
    pub svn: u32,
    /// Component version associated with the image.
    pub version: u32,
    /// Metadata control flags.
    pub flags: ImageMetadataFlags,
}

impl ImageMetadata {
    /// Build initial-load metadata for the current load-address authorization path.
    pub const fn initial_load_from_load_address(
        image_size: u32,
        measurement: [u8; IMAGE_MEASUREMENT_DIGEST_SIZE],
    ) -> Self {
        Self {
            operation: MeasurementOperation::InitialLoad,
            source: ImageHashSource::LoadAddress,
            image_size,
            measurement,
            // TODO: replace explicit zeroes when svn/version sources are wired.
            svn: 0,
            version: 0,
            flags: ImageMetadataFlags::EMPTY,
        }
    }

    /// Build component-update metadata from caller-supplied authorization data.
    pub const fn component_update(
        source: ImageHashSource,
        image_size: u32,
        measurement: [u8; IMAGE_MEASUREMENT_DIGEST_SIZE],
        svn: u32,
        version: u32,
    ) -> Self {
        Self {
            operation: MeasurementOperation::ComponentUpdate,
            source,
            image_size,
            measurement,
            svn,
            version,
            flags: ImageMetadataFlags::EMPTY,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_load_metadata_uses_load_address_and_explicit_zero_versions() {
        let measurement = [0xa5; IMAGE_MEASUREMENT_DIGEST_SIZE];

        let metadata = ImageMetadata::initial_load_from_load_address(0x1234, measurement);

        assert_eq!(metadata.operation, MeasurementOperation::InitialLoad);
        assert_eq!(metadata.source, ImageHashSource::LoadAddress);
        assert_eq!(metadata.image_size, 0x1234);
        assert_eq!(metadata.measurement, measurement);
        assert_eq!(metadata.svn, 0);
        assert_eq!(metadata.version, 0);
        assert_eq!(metadata.flags.bits(), 0);
    }

    #[test]
    fn component_update_metadata_preserves_caller_supplied_values() {
        let measurement = [0x5a; IMAGE_MEASUREMENT_DIGEST_SIZE];

        let metadata =
            ImageMetadata::component_update(ImageHashSource::InRequest, 0x2345, measurement, 7, 9);

        assert_eq!(metadata.operation, MeasurementOperation::ComponentUpdate);
        assert_eq!(metadata.source, ImageHashSource::InRequest);
        assert_eq!(metadata.image_size, 0x2345);
        assert_eq!(metadata.measurement, measurement);
        assert_eq!(metadata.svn, 7);
        assert_eq!(metadata.version, 9);
        assert_eq!(metadata.flags.bits(), 0);
    }
}
