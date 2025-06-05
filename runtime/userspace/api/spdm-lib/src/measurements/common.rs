// Licensed under the Apache-2.0 license
use crate::measurements::freeform_manifest::FreeformManifest;
use crate::protocol::{algorithms::AsymAlgo, MeasurementSpecification, SHA384_HASH_SIZE};
use bitfield::bitfield;
use libapi_caliptra::error::CaliptraApiError;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const SPDM_MAX_MEASUREMENT_RECORD_SIZE: u32 = 0xFFFFFF;
pub const SPDM_MEASUREMENT_MANIFEST_INDEX: u8 = 0xFD;
pub const SPDM_DEVICE_MODE_INDEX: u8 = 0xFE;

#[derive(Debug, PartialEq)]
pub enum MeasurementsError {
    InvalidIndex,
    InvalidOffset,
    InvalidSize,
    InvalidBuffer,
    InvalidOperation,
    InvalidSlotId,
    MeasurementSizeMismatch,
    CaliptraApi(CaliptraApiError),
}
pub type MeasurementsResult<T> = Result<T, MeasurementsError>;

pub enum MeasurementChangeStatus {
    NoDetection = 0,
    ChangeDetected = 1,
    DetectedNoChange = 2,
}

pub(crate) enum SpdmMeasurements {
    FreeformManifest(FreeformManifest),
}

impl Default for SpdmMeasurements {
    fn default() -> Self {
        SpdmMeasurements::FreeformManifest(FreeformManifest::default())
    }
}

#[allow(dead_code)]
impl SpdmMeasurements {
    /// Returns the total number of measurement blocks.
    ///
    /// # Returns
    /// The total number of measurement blocks.
    pub(crate) fn total_measurement_count(&self) -> usize {
        match self {
            SpdmMeasurements::FreeformManifest(manifest) => manifest.total_measurement_count(),
        }
    }

    /// Returns the measurement block size for the given index.
    /// valid index is 1 to 0xFF.
    /// when index is 0xFF, it returns the size of all measurement blocks.
    ///
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm negotiated.
    /// * `index` - The index of the measurement block.
    /// * `raw_bit_stream` - If true, returns the raw bit stream.
    ///
    /// # Returns
    /// The size of the measurement block.
    pub(crate) async fn measurement_block_size(
        &mut self,
        asym_algo: AsymAlgo,
        index: u8,
        raw_bit_stream: bool,
    ) -> MeasurementsResult<usize> {
        if index == 0 {
            return Ok(0);
        }

        match self {
            SpdmMeasurements::FreeformManifest(manifest) => {
                manifest
                    .measurement_block_size(asym_algo, index, raw_bit_stream)
                    .await
            }
        }
    }

    /// Returns the measurement block for the given index.
    ///
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm negotiated.
    /// * `index` - The index of the measurement block. Should be between 1 and 0xFE.
    /// * `raw_bit_stream` - If true, returns the raw bit stream.
    /// * `offset` - The offset to start reading from.
    /// * `measurement_chunk` - The buffer to store the measurement block.
    ///
    /// # Returns
    /// A result indicating success or failure.
    pub(crate) async fn measurement_block(
        &mut self,
        asym_algo: AsymAlgo,
        index: u8,
        raw_bit_stream: bool,
        offset: usize,
        measurement_chunk: &mut [u8],
    ) -> MeasurementsResult<usize> {
        match self {
            SpdmMeasurements::FreeformManifest(manifest) => {
                manifest
                    .measurement_block(asym_algo, index, raw_bit_stream, offset, measurement_chunk)
                    .await
            }
        }
    }

    /// Returns the measurement summary hash.
    /// This is a hash of all the measurement blocks
    ///
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm negotiated.
    /// * `hash` - The buffer to store the hash.
    /// * `measurement_summary_hash_type` - The type of the measurement summary hash to be calculated.
    ///   1 - TCB measurements only
    ///   0xFF - All measurements
    ///
    /// # Returns
    /// A result indicating success or failure.
    pub(crate) async fn measurement_summary_hash(
        &mut self,
        asym_algo: AsymAlgo,
        measurement_summary_hash_type: u8,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> MeasurementsResult<()> {
        match self {
            SpdmMeasurements::FreeformManifest(manifest) => {
                manifest
                    .measurement_summary_hash(asym_algo, measurement_summary_hash_type, hash)
                    .await
            }
        }
    }
}

// From table 55 (SPDM 1.3.2) - DMTFSpecMeasurementValueType
pub enum MeasurementValueType {
    ImmutableRom = 0,
    MutableFirmware = 1,
    HwConfig = 2,
    FwConfig = 3,
    FreeformManifest = 4,
    StructuredDebugDeviceMode = 5,
    MutFwVersionNumbet = 6,
    MutFwSecurityVersionNumber = 7,
    HashExtendedMeasurement = 8,
    Informational = 9,
    StructuredManifest = 10,
}

bitfield! {
#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
struct DmtfSpecMeasurementValueType(u8);
    impl Debug;
    u8;
    mea_val_type, set_meas_val_type: 6, 0; // [6:0] - DMTFSpecMeasurementValueType
    meas_val_repr, set_meas_val_repr: 7, 7; // [7] - digest/raw bit stream
}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C, packed)]
struct DmtfSpecMeasurementValueHeader {
    value_type: DmtfSpecMeasurementValueType,
    value_size: u16, // [23:8] - size of the measurement value
}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C, packed)]
pub struct DmtfMeasurementBlockMetadata {
    index: u8,
    meas_specification: MeasurementSpecification,
    meas_size: u16,
    meas_val_hdr: DmtfSpecMeasurementValueHeader,
}

impl DmtfMeasurementBlockMetadata {
    pub fn new(
        index: u8,
        meas_value_size: u16,
        meas_value_dgst: bool,
        meas_value_type: MeasurementValueType,
    ) -> MeasurementsResult<Self> {
        if index == 0 || index > 0xFE {
            return Err(MeasurementsError::InvalidIndex);
        }

        let mut meas_block_common = DmtfMeasurementBlockMetadata {
            index,
            ..Default::default()
        };
        meas_block_common
            .meas_specification
            .set_dmtf_measurement_spec(1);
        meas_block_common.meas_size =
            meas_value_size + size_of::<DmtfSpecMeasurementValueHeader>() as u16;

        // If digest, repr = 0, raw bit stream = 1
        meas_block_common
            .meas_val_hdr
            .value_type
            .set_meas_val_repr(u8::from(!meas_value_dgst));
        meas_block_common
            .meas_val_hdr
            .value_type
            .set_meas_val_type(meas_value_type as u8);
        meas_block_common.meas_val_hdr.value_size = meas_value_size;

        Ok(meas_block_common)
    }

    pub fn measurement_block_value_hdr_size() -> usize {
        size_of::<DmtfSpecMeasurementValueHeader>()
    }
}
