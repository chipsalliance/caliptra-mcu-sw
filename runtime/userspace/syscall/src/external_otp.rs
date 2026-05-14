// Licensed under the Apache-2.0 license

//! # ExternalOTP: An interface for accessing external OTP (One-Time Programmable) storage.
//!
//! This module provides userspace access to the ExternalOTP peripheral, which
//! models SoC-specific immutable storage external to Caliptra's built-in OTP
//! controller. Storage is organized into partitions, each with a defined size.
//! Each read or write operates on a single u32 (4 bytes).

use crate::DefaultSyscalls;
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use core::marker::PhantomData;

/// Driver number for the ExternalOTP capsule.
pub const EXTERNAL_OTP_DRIVER_NUM: u32 = 0xD100_0000;

mod cmd {
    pub const EXISTS: u32 = 0;
    pub const SET_PARTITION: u32 = 1;
    pub const READ: u32 = 2;
    pub const WRITE: u32 = 3;
    pub const GET_PARTITION_SIZE: u32 = 4;
    pub const GET_PARTITION_COUNT: u32 = 5;
    pub const LOCK_PARTITION: u32 = 6;
    pub const IS_PARTITION_LOCKED: u32 = 7;
}

/// Userspace interface to the ExternalOTP peripheral.
pub struct ExternalOtp<S: Syscalls = DefaultSyscalls> {
    syscall: PhantomData<S>,
    driver_num: u32,
}

impl<S: Syscalls> Default for ExternalOtp<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Syscalls> ExternalOtp<S> {
    pub fn new() -> Self {
        Self {
            syscall: PhantomData,
            driver_num: EXTERNAL_OTP_DRIVER_NUM,
        }
    }

    /// Check if the ExternalOTP driver exists.
    pub fn exists(&self) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::EXISTS, 0, 0).to_result()
    }

    /// Get the number of partitions available.
    pub fn partition_count(&self) -> Result<u32, ErrorCode> {
        S::command(self.driver_num, cmd::GET_PARTITION_COUNT, 0, 0).to_result::<u32, ErrorCode>()
    }

    /// Get the size (in bytes) of a specific partition.
    pub fn partition_size(&self, partition_id: u32) -> Result<u32, ErrorCode> {
        S::command(self.driver_num, cmd::GET_PARTITION_SIZE, partition_id, 0)
            .to_result::<u32, ErrorCode>()
    }

    /// Read a u32 from a partition at the given byte offset.
    pub fn read(&self, partition_id: u32, offset: u32) -> Result<u32, ErrorCode> {
        S::command(self.driver_num, cmd::SET_PARTITION, partition_id, 0)
            .to_result::<(), ErrorCode>()?;

        S::command(self.driver_num, cmd::READ, offset, 0).to_result::<u32, ErrorCode>()
    }

    /// Write a u32 to a partition at the given byte offset.
    pub fn write(&self, partition_id: u32, offset: u32, value: u32) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::SET_PARTITION, partition_id, 0)
            .to_result::<(), ErrorCode>()?;

        S::command(self.driver_num, cmd::WRITE, offset, value).to_result::<(), ErrorCode>()
    }

    /// Lock a partition, preventing further writes.
    ///
    /// Once locked, subsequent `write()` calls to this partition will fail.
    pub fn lock_partition(&self, partition_id: u32) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::LOCK_PARTITION, partition_id, 0)
            .to_result::<(), ErrorCode>()
    }

    /// Check whether a partition is locked.
    ///
    /// Returns `true` if the partition is locked, `false` otherwise.
    pub fn is_partition_locked(&self, partition_id: u32) -> Result<bool, ErrorCode> {
        let val = S::command(self.driver_num, cmd::IS_PARTITION_LOCKED, partition_id, 0)
            .to_result::<u32, ErrorCode>()?;
        Ok(val != 0)
    }
}
