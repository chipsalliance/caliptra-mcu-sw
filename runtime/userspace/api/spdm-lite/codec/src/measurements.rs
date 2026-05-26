// Licensed under the Apache-2.0 license

//! GET_MEASUREMENTS / MEASUREMENTS wire types (DSP0274 §10.11).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    REQUESTER_CONTEXT_LEN, ReqRespCode, ResponseBody, SPDM_NONCE_LEN, WireError, WireWriter,
};

// ---- Constants -------------------------------------------------------------

/// DMTF measurement block metadata size (7 bytes).
pub const MEAS_BLOCK_METADATA_SIZE: usize = 7;

/// Maximum measurement record length (24-bit field).
pub const SPDM_MAX_MEASUREMENT_RECORD_SIZE: u32 = 0xFF_FFFF;

// ---- Request ---------------------------------------------------------------

/// GET_MEASUREMENTS request fixed fields (after SPDM header).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct GetMeasurementsReqBody {
    /// Bit 0: signature requested
    /// Bit 1: raw bitstream requested
    pub attributes: u8,
    /// 0x00 = total count only; 0x01..0xFE = specific index; 0xFF = all
    pub measurement_operation: u8,
}

impl GetMeasurementsReqBody {
    /// Whether a signature is requested (bit 0).
    #[inline]
    pub fn signature_requested(&self) -> bool {
        self.attributes & 0x01 != 0
    }

    /// Whether raw bitstream is requested (bit 1).
    #[inline]
    pub fn raw_bitstream_requested(&self) -> bool {
        self.attributes & 0x02 != 0
    }
}

const _: () = assert!(core::mem::size_of::<GetMeasurementsReqBody>() == 2);

// ---- Response builder ------------------------------------------------------

/// MEASUREMENTS response builder.
///
/// The response layout (DSP0274 §10.11.2):
/// ```text
/// [ Param1(1) | Param2(1) | NumberOfBlocks(1) | MeasRecordLen(3) |
///   MeasurementRecord(variable) | Nonce(32) | OpaqueLen(2) |
///   OpaqueData(variable) | RequesterContext(8, V1.3+) | Signature(96, optional) ]
/// ```
pub struct MeasurementsRsp<'a> {
    /// Total number of measurement indices (param1 when op=0).
    pub total_number_of_measurement: u8,
    /// SlotID[3:0] | ContentChanged[5:4] in param2.
    pub slot_id: u8,
    /// Content changed indicator (0=no detection, 1=change, 2=no change).
    pub content_changed: u8,
    /// Number of measurement blocks in the record.
    pub number_of_blocks: u8,
    /// Serialized measurement record bytes.
    pub measurement_record: &'a [u8],
    /// Responder nonce (32 bytes).
    pub nonce: &'a [u8; SPDM_NONCE_LEN],
    /// Opaque data (usually empty).
    pub opaque_data: &'a [u8],
    /// RequesterContext (V1.3+).
    pub requester_context: Option<&'a [u8; REQUESTER_CONTEXT_LEN]>,
    /// Signature (present only if signature was requested).
    pub signature: &'a [u8],
}

impl ResponseBody for MeasurementsRsp<'_> {
    const RESPONSE_CODE: ReqRespCode = ReqRespCode::MEASUREMENTS;

    fn body_size(&self) -> usize {
        // param1(1) + param2(1) + number_of_blocks(1) + meas_record_len(3)
        // + measurement_record + nonce(32) + opaque_len(2)
        // + opaque_data + requester_context(opt) + signature(opt)
        1 + 1 + 1 + 3 + self.measurement_record.len() + SPDM_NONCE_LEN + 2
            + self.opaque_data.len()
            + self.requester_context_len()
            + self.signature.len()
    }

    fn encode_body(&self, w: &mut WireWriter<'_>) -> Result<(), WireError> {
        // Param1: TotalNumberOfMeasurement
        w.write_bytes(&[self.total_number_of_measurement])?;
        // Param2: SlotID[3:0] | ContentChanged[5:4]
        let param2 = (self.slot_id & 0x0F) | ((self.content_changed & 0x03) << 4);
        w.write_bytes(&[param2])?;
        // NumberOfBlocks
        w.write_bytes(&[self.number_of_blocks])?;
        // MeasurementRecordLength (3 bytes LE)
        let rec_len = self.measurement_record.len() as u32;
        w.write_bytes(&[
            (rec_len & 0xFF) as u8,
            ((rec_len >> 8) & 0xFF) as u8,
            ((rec_len >> 16) & 0xFF) as u8,
        ])?;
        // MeasurementRecord
        w.write_bytes(self.measurement_record)?;
        // Nonce
        w.write_bytes(self.nonce)?;
        // OpaqueDataLength (2 bytes LE)
        let opaque_len = self.opaque_data.len() as u16;
        w.write_bytes(&opaque_len.to_le_bytes())?;
        // OpaqueData
        if !self.opaque_data.is_empty() {
            w.write_bytes(self.opaque_data)?;
        }
        // RequesterContext (V1.3+)
        if let Some(ctx) = self.requester_context {
            w.write_bytes(ctx)?;
        }
        // Signature
        if !self.signature.is_empty() {
            w.write_bytes(self.signature)?;
        }
        Ok(())
    }
}

impl MeasurementsRsp<'_> {
    fn requester_context_len(&self) -> usize {
        if self.requester_context.is_some() {
            REQUESTER_CONTEXT_LEN
        } else {
            0
        }
    }
}

// ---- DMTF Measurement Block Metadata (7 bytes) -----------------------------

/// DMTF measurement block metadata header (DSP0274 Table 55).
///
/// Layout:
/// ```text
/// [Index(1) | MeasurementSpecification(1) | MeasurementSize(2) |
///  DMTFSpecMeasurementValueType(1) | DMTFSpecMeasurementValueSize(2)]
/// ```
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct DmtfMeasurementBlockHeader {
    /// Measurement index (1..=0xFE).
    pub index: u8,
    /// MeasurementSpecification (bit 0 = DMTF).
    pub measurement_specification: u8,
    /// MeasurementSize = sizeof(ValueType) + sizeof(ValueSize) + value_size
    /// i.e. 3 + value_size (stored LE).
    pub measurement_size: [u8; 2],
    /// Bit[6:0] = value type, Bit[7] = 0 for digest, 1 for raw.
    pub value_type: u8,
    /// Size of the measurement value (LE 16-bit).
    pub value_size: [u8; 2],
}

const _: () = assert!(core::mem::size_of::<DmtfMeasurementBlockHeader>() == MEAS_BLOCK_METADATA_SIZE);

impl DmtfMeasurementBlockHeader {
    /// Create a new measurement block header.
    ///
    /// * `index` — measurement index (1..=0xFE)
    /// * `is_raw` — true for raw bitstream, false for digest
    /// * `meas_value_type` — DMTF value type (0..=10)
    /// * `value_len` — length of the measurement value
    pub fn new(index: u8, is_raw: bool, meas_value_type: u8, value_len: u16) -> Self {
        let meas_size = 3u16 + value_len; // value_type(1) + value_size(2) + value
        Self {
            index,
            measurement_specification: 0x01, // DMTF
            measurement_size: meas_size.to_le_bytes(),
            value_type: meas_value_type | (if is_raw { 0x80 } else { 0x00 }),
            value_size: value_len.to_le_bytes(),
        }
    }
}
