// Licensed under the Apache-2.0 license

//! Hardware Interface Layer for ExternalOTP peripheral.
//!
//! This trait abstracts partition-based OTP storage that lives outside Caliptra's
//! built-in OTP controller. Integrators implement this trait for their platform's
//! actual fuse controller, EPROM, or secure storage element.
//!
//! Operations that access the backing store (`read`, `write`, `lock_partition`,
//! `is_partition_locked`) are **asynchronous**: the method starts the operation
//! and returns immediately; the result is delivered via the [`ExternalOtpClient`]
//! callback. Metadata queries (`partition_info`, `partition_count`) are
//! synchronous because they do not touch the backing store.

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
    /// The driver is busy with another operation.
    Busy,
}

impl From<ExternalOtpError> for ErrorCode {
    fn from(e: ExternalOtpError) -> Self {
        match e {
            ExternalOtpError::WriteProtected => ErrorCode::NOSUPPORT,
            ExternalOtpError::OutOfBounds => ErrorCode::INVAL,
            ExternalOtpError::InvalidPartition => ErrorCode::INVAL,
            ExternalOtpError::PartitionLocked => ErrorCode::NOSUPPORT,
            ExternalOtpError::HardwareError => ErrorCode::FAIL,
            ExternalOtpError::Busy => ErrorCode::BUSY,
        }
    }
}

/// Callback trait for asynchronous ExternalOtp operations.
pub trait ExternalOtpClient {
    /// Called when a `read` operation completes.
    fn read_done(&self, result: Result<u32, ExternalOtpError>);

    /// Called when a `write` operation completes.
    fn write_done(&self, result: Result<(), ExternalOtpError>);

    /// Called when a `lock_partition` operation completes.
    fn lock_done(&self, result: Result<(), ExternalOtpError>);

    /// Called when an `is_partition_locked` query completes.
    fn lock_check_done(&self, result: Result<bool, ExternalOtpError>);
}

/// Hardware interface for an external OTP peripheral with partition-based access.
///
/// # Overview
///
/// Real OTP controllers organize storage into partitions with defined sizes and
/// access policies. This trait models that structure. Each partition is identified
/// by a `u32` ID and has a fixed size.
///
/// # Asynchronous Model
///
/// Operations that access the backing store are asynchronous. The method
/// validates parameters and starts the operation, returning `Ok(())` on
/// success or an error if the parameters are invalid or the driver is busy.
/// The actual result is delivered via the [`ExternalOtpClient`] callback.
///
/// # For Integrators
///
/// Implement this trait for your platform's actual OTP/EPROM driver. Your
/// implementation should:
/// - Enforce write-once semantics at the hardware level
/// - Map partition IDs to physical fuse/EPROM regions
/// - Return `HardwareError` for controller failures
pub trait ExternalOtp<'a> {
    /// Set the client that receives operation-complete callbacks.
    fn set_client(&self, client: &'a dyn ExternalOtpClient);

    /// Start reading a u32 from a partition at the given byte offset.
    ///
    /// The result is delivered via [`ExternalOtpClient::read_done`].
    fn read(&self, partition: u32, offset: u32) -> Result<(), ExternalOtpError>;

    /// Start writing a u32 to a partition at the given byte offset.
    ///
    /// The result is delivered via [`ExternalOtpClient::write_done`].
    fn write(&self, partition: u32, offset: u32, value: u32) -> Result<(), ExternalOtpError>;

    /// Start locking a partition, preventing further writes.
    ///
    /// The result is delivered via [`ExternalOtpClient::lock_done`].
    fn lock_partition(&self, partition: u32) -> Result<(), ExternalOtpError>;

    /// Start checking whether a partition is locked.
    ///
    /// The result is delivered via [`ExternalOtpClient::lock_check_done`].
    fn is_partition_locked(&self, partition: u32) -> Result<(), ExternalOtpError>;

    /// Get metadata for a specific partition (synchronous).
    fn partition_info(&self, partition: u32) -> Option<&ExternalOtpPartitionInfo>;

    /// Get the total number of partitions (synchronous).
    fn partition_count(&self) -> usize;
}
