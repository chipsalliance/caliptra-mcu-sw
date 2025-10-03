// Licensed under the Apache-2.0 license

use crate::protocol::MeasurementSpecification;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const SPDM_MAX_MEASUREMENT_RECORD_SIZE: u32 = 0xFFFFFF;
pub const SPDM_MEASUREMENT_MANIFEST_INDEX: u8 = 0xFD;
pub const SPDM_DEVICE_MODE_INDEX: u8 = 0xFE;
pub const MEAS_BLOCK_METADATA_SIZE: usize = size_of::<DmtfMeasurementBlockMetadata>();

bitfield! {
#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C)]
pub struct DmtfSpecMeasurementValueType(u8);
    impl Debug;
    u8;
    meas_val_type, set_meas_val_type: 6, 0; // [6:0] - DMTFSpecMeasurementValueType
    meas_val_repr, set_meas_val_repr: 7, 7; // [7] - digest/raw bit stream
}

#[derive(IntoBytes, FromBytes, Immutable, Default)]
#[repr(C, packed)]
pub struct DmtfSpecMeasurementValueHeader {
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
    ) -> Option<Self> {
        if index == 0 || index > 0xFE {
            return None;
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

        Some(meas_block_common)
    }

    pub fn measurement_block_value_hdr_size() -> usize {
        size_of::<DmtfSpecMeasurementValueHeader>()
    }
}

pub enum MeasurementChangeStatus {
    NoDetection = 0,
    ChangeDetected = 1,
    DetectedNoChange = 2,
}

// From table 55 (SPDM 1.3.2) - DMTFSpecMeasurementValueType
#[derive(PartialEq, Clone)]
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
