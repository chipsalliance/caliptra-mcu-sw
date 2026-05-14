// Licensed under the Apache-2.0 license

//! Hardware Interface Layer for ExternalOTP peripheral.
//!
//! This trait abstracts partition-based OTP storage that lives outside Caliptra's
//! built-in OTP controller. Integrators implement this trait for their platform's
//! actual fuse controller, EPROM, or secure storage element.

use kernel::ErrorCode;

/// Metadata describing a single OTP partition.
#[derive(Debug, Clone, Copy)]
pub struct ExternalOtpPartitionInfo {
    /// Unique partition identifier (integrator-defined).
    pub id: u32,
    /// Size of this partition in bytes.
    pub size: u32,
}

/// Errors returned by ExternalOtp operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalOtpError {
    /// Attempted to write to a byte that has already been programmed (write-once violation).
    WriteProtected,
    /// The requested offset + length exceeds the partition bounds.
    OutOfBounds,
    /// The specified partition ID does not exist.
    InvalidPartition,
    /// The partition is locked and cannot be written to.
    PartitionLocked,
    /// An underlying hardware error occurred.
    HardwareError,
}

impl From<ExternalOtpError> for ErrorCode {
    fn from(e: ExternalOtpError) -> Self {
        match e {
            ExternalOtpError::WriteProtected => ErrorCode::NOSUPPORT,
            ExternalOtpError::OutOfBounds => ErrorCode::INVAL,
            ExternalOtpError::InvalidPartition => ErrorCode::INVAL,
            ExternalOtpError::PartitionLocked => ErrorCode::NOSUPPORT,
            ExternalOtpError::HardwareError => ErrorCode::FAIL,
        }
    }
}

/// Hardware interface for an external OTP peripheral with partition-based access.
///
/// # Overview
///
/// Real OTP controllers organize storage into partitions with defined sizes and
/// access policies. This trait models that structure. Each partition is identified
/// by a `u32` ID and has a fixed size.
///
/// # For Integrators
///
/// Replace the reference implementation (`ExtSramBackedExternalOtp`) with your
/// platform's actual driver. Your implementation should:
/// - Enforce write-once semantics at the hardware level
/// - Map partition IDs to physical fuse/EPROM regions
/// - Return `HardwareError` for controller failures
pub trait ExternalOtp {
    /// Read a u32 from a partition at the given byte offset.
    ///
    /// # Arguments
    /// - `partition`: The partition ID to read from.
    /// - `offset`: Byte offset within the partition (must be 4-byte aligned).
    ///
    /// # Returns
    /// The 32-bit value at the given offset, or an error.
    fn read(&self, partition: u32, offset: u32) -> Result<u32, ExternalOtpError>;

    /// Write a u32 to a partition at the given byte offset.
    ///
    /// # Arguments
    /// - `partition`: The partition ID to write to.
    /// - `offset`: Byte offset within the partition (must be 4-byte aligned).
    /// - `value`: The 32-bit value to write.
    fn write(&self, partition: u32, offset: u32, value: u32) -> Result<(), ExternalOtpError>;

    /// Lock a partition, preventing further writes.
    ///
    /// Once locked, any subsequent `write()` call to this partition will return
    /// `PartitionLocked`. Locking is irreversible for the current power cycle.
    fn lock_partition(&self, partition: u32) -> Result<(), ExternalOtpError>;

    /// Check whether a partition is locked.
    fn is_partition_locked(&self, partition: u32) -> Result<bool, ExternalOtpError>;

    /// Get metadata for a specific partition.
    fn partition_info(&self, partition: u32) -> Option<&ExternalOtpPartitionInfo>;

    /// Get the total number of partitions.
    fn partition_count(&self) -> usize;
}
