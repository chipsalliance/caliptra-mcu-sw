// Licensed under the Apache-2.0 license

/// Measurement block to hold the Freeform/Structured manifest data has the
/// following structure:
/// _______________________________________________________________________________________________________
/// | - index: SPDM_MEASUREMENT_MANIFEST_INDEX                                                             |
/// | - MeasurementSpecification: 01h (DMTF)                                                               |
/// |           - DMTFSpecMeasurementValueType[6:0]: 04h (Freeform Manifest) / 0x0A (Structured Manifest)  |
/// |           - DMTFSpecMeasurementValueType[7]  : 1b  (raw bit-stream)                                  |
/// | - MeasurementSize: 2 bytes (size of manifest in DMTF measurement specification format)               |
/// | - MeasurementBlock: measurement block (manifest in DMTF measurement specification format)            |
/// _______________________________________________________________________________________________________|
extern crate alloc;

use crate::protocol::*;
use alloc::boxed::Box;
use async_trait::async_trait;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libapi_caliptra::error::CaliptraApiError;
use libapi_caliptra::mailbox_api::MAX_CRYPTO_MBOX_DATA_SIZE;
use zerocopy::IntoBytes;

// Needs to be adjusted based on actual max size of measurement record when PQC is added
const MAX_MEASUREMENT_RECORD_BUF_SIZE: usize = 4096;

#[derive(Debug, PartialEq)]
pub enum MeasurementsError {
    InvalidIndex,
    InvalidOffset,
    InvalidSize,
    InvalidBuffer,
    BufferTooSmall,
    InvalidOperation,
    InvalidSlotId,
    InvalidParam,
    InvalidInput,
    MissingParam(&'static str),
    MeasurementSizeMismatch,
    CaliptraApi(CaliptraApiError),
}
pub type MeasurementsResult<T> = Result<T, MeasurementsError>;

#[async_trait]
pub trait SpdmMeasurementValue {
    /// Retrieves the measurement value for the specified index.
    ///
    /// # Arguments
    /// * `index` - The index of the measurement value to retrieve.
    /// * `nonce` - An optional nonce to include in the measurement value depending on the type of measurement.
    /// * `asym_algo` - The asymmetric algorithm to use for signing the measurement value if signature is needed
    /// * `measurement` - The buffer to store the measurement value.
    ///
    /// # Returns
    /// The size of the measurement value written to the buffer.
    async fn get_measurement_value(
        &mut self,
        index: u8,
        nonce: &[u8],
        asym_algo: AsymAlgo,
        measurement: &mut [u8],
    ) -> MeasurementsResult<usize>;
}

/// Information about each measurement value
#[derive(Clone)]
pub struct MeasurementValueInfo {
    pub value_type: MeasurementValueType,
    pub is_dgst: bool,
    pub is_tcb: bool,
    pub meas_index: u8,
}

impl MeasurementValueInfo {
    /// Create a new measurement value info with validation
    pub fn new(
        value_type: MeasurementValueType,
        is_dgst: bool,
        is_tcb: bool,
        meas_index: u8,
    ) -> MeasurementsResult<Self> {
        // Additional validation: certain types should use reserved indices
        match value_type {
            MeasurementValueType::FreeformManifest | MeasurementValueType::StructuredManifest => {
                if meas_index != SPDM_MEASUREMENT_MANIFEST_INDEX {
                    return Err(MeasurementsError::InvalidIndex);
                }
            }
            MeasurementValueType::StructuredDebugDeviceMode => {
                if meas_index != SPDM_DEVICE_MODE_INDEX {
                    return Err(MeasurementsError::InvalidIndex);
                }
            }
            _ => {
                // Regular measurements should not use reserved indices
                if !(1..0xF0).contains(&meas_index) {
                    return Err(MeasurementsError::InvalidIndex);
                }
            }
        }

        Ok(MeasurementValueInfo {
            value_type,
            is_dgst,
            is_tcb,
            meas_index,
        })
    }

    /// Create manifest measurement info (uses reserved index 0xFD)
    pub fn freeform_manifest(is_dgst: bool, is_tcb: bool) -> Self {
        MeasurementValueInfo {
            value_type: MeasurementValueType::FreeformManifest,
            is_dgst,
            is_tcb,
            meas_index: SPDM_MEASUREMENT_MANIFEST_INDEX,
        }
    }

    pub fn structured_manifest(is_dgst: bool, is_tcb: bool) -> Self {
        MeasurementValueInfo {
            value_type: MeasurementValueType::StructuredManifest,
            is_dgst,
            is_tcb,
            meas_index: SPDM_MEASUREMENT_MANIFEST_INDEX,
        }
    }

    /// Create device mode measurement info (uses reserved index 0xFE)  
    pub fn device_mode(is_dgst: bool, is_tcb: bool) -> Self {
        MeasurementValueInfo {
            value_type: MeasurementValueType::StructuredDebugDeviceMode,
            is_dgst,
            is_tcb,
            meas_index: SPDM_DEVICE_MODE_INDEX,
        }
    }
}

/// Structure to hold and retrieve SPDM measurements information
pub struct SpdmMeasurements<'a> {
    meas_value_info: &'a [MeasurementValueInfo],
    meas_value: &'a mut dyn SpdmMeasurementValue,
    nonce: Option<[u8; SPDM_NONCE_LEN]>,
    asym_algo: Option<AsymAlgo>,
    spdm_version: Option<SpdmVersion>,
    measurement_record: MeasurementRecord,
}

struct MeasurementRecord {
    data: [u8; MAX_MEASUREMENT_RECORD_BUF_SIZE], // Fixed-size array
    length: usize,
    current_index: u8,
    valid: bool,
}

impl Default for MeasurementRecord {
    fn default() -> Self {
        MeasurementRecord {
            data: [0u8; MAX_MEASUREMENT_RECORD_BUF_SIZE],
            length: 0,
            current_index: 0,
            valid: false,
        }
    }
}

impl MeasurementRecord {
    fn is_valid(&self, index: u8) -> bool {
        self.current_index == index && self.length > 0 && self.valid
    }

    fn reset(&mut self) {
        self.length = 0;
        self.current_index = 0;
        self.valid = false;
        self.data.fill(0);
    }

    fn add_measurement_block(
        &mut self,
        index: u8,
        is_dgst: bool,
        value_type: MeasurementValueType,
        value_len: usize,
    ) -> MeasurementsResult<()> {
        let offset = self.length;
        let needed = MEAS_BLOCK_METADATA_SIZE + value_len;
        if self.data.len().saturating_sub(offset) < needed {
            return Err(MeasurementsError::BufferTooSmall);
        }

        let metadata =
            DmtfMeasurementBlockMetadata::new(index, value_len as u16, is_dgst, value_type)
                .ok_or(MeasurementsError::InvalidIndex)?;
        self.data[offset..offset + MEAS_BLOCK_METADATA_SIZE].copy_from_slice(metadata.as_bytes());

        self.length += needed;

        Ok(())
    }

    fn set_valid(&mut self, index: u8) {
        self.current_index = index;
        self.valid = true;
    }
}

impl<'a> SpdmMeasurements<'a> {
    /// Creates a new instance of `SpdmMeasurements`.
    ///
    /// # Arguments
    /// * `meas_value_info` - A slice of `MeasurementValueInfo` representing each measurement value.
    /// * `meas_value` - A mutable reference to a type that implements the `SpdmMeasurementValue` trait.
    ///
    /// # Returns
    /// A new instance of `SpdmMeasurements`.
    pub fn new(
        meas_value_info: &'a [MeasurementValueInfo],
        meas_value: &'a mut dyn SpdmMeasurementValue,
    ) -> Self {
        SpdmMeasurements {
            meas_value_info,
            meas_value,
            nonce: None,
            asym_algo: None,
            spdm_version: None,
            measurement_record: MeasurementRecord::default(),
        }
    }

    /// Sets the nonce to be included in the measurement value.
    pub(crate) fn set_nonce(&mut self, nonce: [u8; SPDM_NONCE_LEN]) {
        self.nonce = Some(nonce);
        self.measurement_record.valid = false;
    }

    pub(crate) fn set_spdm_version(&mut self, version: SpdmVersion) {
        self.spdm_version = Some(version);
    }

    pub(crate) fn set_asym_algo(&mut self, asym_algo: AsymAlgo) {
        self.asym_algo = Some(asym_algo);
    }

    /// Returns the total number of measurement blocks.
    ///
    /// # Returns
    /// The total number of measurement blocks.
    pub(crate) fn total_measurement_count(&self) -> usize {
        self.meas_value_info.len()
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
        _raw_bit_stream: bool,
    ) -> MeasurementsResult<usize> {
        if index == 0 {
            return Ok(0);
        }

        let len = if self.measurement_record.is_valid(index) {
            // Special case for freeform manifest
            self.measurement_record.length
        } else {
            if index == 0xFF {
                // Size of all measurement blocks
                self.fetch_all_measurement_blocks().await?;
            } else {
                // Size of specific measurement block
                self.fetch_measurement_block(index, false).await?;
            }
            self.measurement_record.length
        };

        Ok(len)
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
        index: u8,
        _raw_bit_stream: bool,
        offset: usize,
        measurement_chunk: &mut [u8],
    ) -> MeasurementsResult<usize> {
        if !self.measurement_record.is_valid(index) {
            if index == 0xFF {
                // Fetch all measurement blocks
                self.fetch_all_measurement_blocks().await?;
            } else {
                // Fetch specific measurement block
                self.fetch_measurement_block(index, false).await?;
            }
        }

        if offset >= self.measurement_record.length {
            return Err(MeasurementsError::InvalidOffset);
        }

        let end = self
            .measurement_record
            .length
            .min(offset + measurement_chunk.len());

        let chunk_size = end - offset;
        measurement_chunk[..chunk_size].copy_from_slice(&self.measurement_record.data[offset..end]);
        Ok(chunk_size)
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
        measurement_summary_hash_type: u8,
        hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> MeasurementsResult<()> {
        if measurement_summary_hash_type != 1 && measurement_summary_hash_type != 0xFF {
            return Err(MeasurementsError::InvalidParam);
        }

        // Fetch the required measurement blocks freshly for summary hash
        self.measurement_record.reset();

        if measurement_summary_hash_type == 1 {
            // Only TCB measurements
            for measurement_info in self.meas_value_info.iter() {
                if measurement_info.is_tcb {
                    self.fetch_measurement_block(measurement_info.meas_index, true)
                        .await?;
                }
            }
        } else {
            self.fetch_all_measurement_blocks().await?;
        }

        let mut hash_ctx = HashContext::new();
        let mut offset = 0;
        let meas_rec_len = self.measurement_record.length;

        while offset < meas_rec_len {
            let chunk_size = MAX_CRYPTO_MBOX_DATA_SIZE.min(meas_rec_len - offset);

            if offset == 0 {
                hash_ctx
                    .init(
                        HashAlgoType::SHA384,
                        Some(&self.measurement_record.data[..chunk_size]),
                    )
                    .await
                    .map_err(MeasurementsError::CaliptraApi)?;
            } else {
                let chunk = &self.measurement_record.data[offset..offset + chunk_size];
                hash_ctx
                    .update(chunk)
                    .await
                    .map_err(MeasurementsError::CaliptraApi)?;
            }

            offset += chunk_size;
        }

        hash_ctx
            .finalize(hash)
            .await
            .map_err(MeasurementsError::CaliptraApi)
    }

    fn meas_value_info(&self, index: u8) -> MeasurementsResult<MeasurementValueInfo> {
        self.meas_value_info
            .iter()
            .find(|info| info.meas_index == index)
            .cloned()
            .ok_or(MeasurementsError::InvalidIndex)
    }

    async fn fetch_measurement_block(&mut self, index: u8, append: bool) -> MeasurementsResult<()> {
        let asym_algo = self
            .asym_algo
            .ok_or(MeasurementsError::MissingParam("AsymAlgo"))?;

        let nonce = self.nonce.unwrap_or_default();

        let meas_info = self.meas_value_info(index)?;

        let meas_value_type = if meas_info.value_type == MeasurementValueType::StructuredManifest {
            let spdm_version = self
                .spdm_version
                .ok_or(MeasurementsError::MissingParam("SpdmVersion"))?;
            if spdm_version < SpdmVersion::V13 {
                MeasurementValueType::FreeformManifest
            } else {
                MeasurementValueType::StructuredManifest
            }
        } else {
            meas_info.value_type
        };

        if !append {
            self.measurement_record.reset();
        }

        let offset = self.measurement_record.length;
        let meas_value_offset = offset + MEAS_BLOCK_METADATA_SIZE;
        let remaining = self
            .measurement_record
            .data
            .len()
            .saturating_sub(meas_value_offset);
        if remaining == 0 {
            Err(MeasurementsError::BufferTooSmall)?;
        }
        let meas_value_slice =
            &mut self.measurement_record.data[meas_value_offset..meas_value_offset + remaining];

        let meas_value_size = self
            .meas_value
            .get_measurement_value(meas_info.meas_index, &nonce, asym_algo, meas_value_slice)
            .await?;

        if meas_value_size > remaining {
            Err(MeasurementsError::BufferTooSmall)?;
        }

        // Add spdm measurement block metadata and update length.
        self.measurement_record.add_measurement_block(
            meas_info.meas_index,
            meas_info.is_dgst,
            meas_value_type,
            meas_value_size,
        )?;

        // Set current_index/valid so is_valid() reflects the freshly filled record.
        // - For single-block fetches (append == false) mark the record valid for that index so future calls can reuse.
        if !append {
            self.measurement_record.set_valid(meas_info.meas_index);
        }

        Ok(())
    }

    async fn fetch_all_measurement_blocks(&mut self) -> MeasurementsResult<()> {
        self.measurement_record.reset();
        for info in self.meas_value_info.iter() {
            self.fetch_measurement_block(info.meas_index, true).await?;
        }
        self.measurement_record.set_valid(0xFF);

        Ok(())
    }
}
