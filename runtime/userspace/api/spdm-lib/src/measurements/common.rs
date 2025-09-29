// Licensed under the Apache-2.0 license

use crate::measurements::ocp_eat::OcpEatManifest;
use crate::measurements::pcr_quote::PcrQuoteManifest;
use crate::protocol::*;
use bitfield::bitfield;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use libapi_caliptra::error::CaliptraApiError;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const SPDM_MAX_MEASUREMENT_RECORD_SIZE: u32 = 0xFFFFFF;
pub const SPDM_MEASUREMENT_MANIFEST_INDEX: u8 = 0xFD;
pub const SPDM_DEVICE_MODE_INDEX: u8 = 0xFE;

#[derive(Debug)]
pub enum MeasurementsError {
    InvalidIndex,
    InvalidOffset,
    InvalidSize,
    InvalidBuffer,
    InvalidOperation,
    InvalidSlotId,
    MissingParam(&'static str),
    MeasurementSizeMismatch,
    CaliptraApi(CaliptraApiError),
    CosetSerializeError,
}
pub type MeasurementsResult<T> = Result<T, MeasurementsError>;

pub enum MeasurementChangeStatus {
    NoDetection = 0,
    ChangeDetected = 1,
    DetectedNoChange = 2,
}

pub enum SpdmMeasurements<'a> {
    PcrQuote(PcrQuoteManifest),
    OcpEat(OcpEatManifest<'a>),
    // Manifest(MeasurementManifest),
}

impl Default for SpdmMeasurements<'_> {
    fn default() -> Self {
        SpdmMeasurements::PcrQuote(PcrQuoteManifest::default())
    }
}

impl SpdmMeasurements<'_> {
    pub(crate) fn set_nonce(&mut self, nonce: [u8; 32]) {
        match self {
            SpdmMeasurements::PcrQuote(pcr_quote) => pcr_quote.set_nonce(nonce),
            SpdmMeasurements::OcpEat(ocp_eat) => ocp_eat.set_nonce(nonce),
        }
    }

    pub(crate) fn set_spdm_version(&mut self, version: SpdmVersion) {
        if let SpdmMeasurements::OcpEat(ocp_eat) = self {
            ocp_eat.set_spdm_version(version);
        }
    }

    pub(crate) fn set_asym_algo(&mut self, asym_algo: AsymAlgo) {
        match self {
            SpdmMeasurements::PcrQuote(pcr_quote) => pcr_quote.set_asym_algo(asym_algo),
            SpdmMeasurements::OcpEat(ocp_eat) => ocp_eat.set_asym_algo(asym_algo),
        }
    }

    /// Returns the total number of measurement blocks.
    ///
    /// # Returns
    /// The total number of measurement blocks.
    pub(crate) fn total_measurement_count(&self) -> usize {
        match self {
            SpdmMeasurements::PcrQuote(pcr_quote) => pcr_quote.total_measurement_count(),
            SpdmMeasurements::OcpEat(ocp_eat) => ocp_eat.total_measurement_count(),
        }
    }

    /// Returns the measurement block size for the given index.
    /// valid index is 1 to 0xFF.
    /// when index is 0xFF, it returns the size of all measurement blocks.
    ///
    /// # Arguments
    /// * `index` - The index of the measurement block.
    /// * `raw_bit_stream` - If true, returns the raw bit stream.
    ///
    /// # Returns
    /// The size of the measurement block.
    pub(crate) async fn measurement_block_size(
        &mut self,
        index: u8,
        raw_bit_stream: bool,
    ) -> MeasurementsResult<usize> {
        if index == 0 {
            return Ok(0);
        }

        match self {
            SpdmMeasurements::PcrQuote(pcr_quote) => {
                pcr_quote
                    .measurement_block_size(index, raw_bit_stream)
                    .await
            }
            SpdmMeasurements::OcpEat(ocp_eat) => {
                ocp_eat.measurement_block_size(index, raw_bit_stream).await
            }
        }
    }

    /// Returns the measurement block for the given index.
    ///
    /// # Arguments
    /// * `index` - The index of the measurement block. Should be between 1 and 0xFE.
    /// * `raw_bit_stream` - If true, returns the raw bit stream.
    /// * `offset` - The offset to start reading from.
    /// * `measurement_chunk` - The buffer to store the measurement block.
    ///
    /// # Returns
    /// A result indicating success or failure.
    pub(crate) async fn measurement_block(
        &mut self,
        index: u8,
        raw_bit_stream: bool,
        offset: usize,
        measurement_chunk: &mut [u8],
    ) -> MeasurementsResult<usize> {
        match self {
            SpdmMeasurements::PcrQuote(pcr_quote) => {
                pcr_quote
                    .measurement_block(index, raw_bit_stream, offset, measurement_chunk)
                    .await
            }
            SpdmMeasurements::OcpEat(ocp_eat) => {
                ocp_eat
                    .measurement_block(index, raw_bit_stream, offset, measurement_chunk)
                    .await
            }
        }
    }

    /// Returns the measurement summary hash.
    /// This is a hash of all the measurement blocks
    ///
    /// # Arguments
    /// * `hash` - The buffer to store the hash.
    /// * `measurement_summary_hash_type` - The type of the measurement summary hash to be calculated.
    ///   1 - TCB measurements only
    ///   0xFF - All measurements
    ///
    /// # Returns
    /// A result indicating success or failure.
    pub(crate) async fn measurement_summary_hash(
        &mut self,
        measurement_summary_hash_type: u8,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> MeasurementsResult<()> {
        match self {
            SpdmMeasurements::PcrQuote(pcr_quote) => {
                pcr_quote
                    .measurement_summary_hash(measurement_summary_hash_type, hash)
                    .await
            }
            SpdmMeasurements::OcpEat(ocp_eat) => {
                ocp_eat
                    .measurement_summary_hash(measurement_summary_hash_type, hash)
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
