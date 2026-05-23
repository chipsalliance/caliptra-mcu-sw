// Licensed under the Apache-2.0 license

//! # ExternalOTP: An async interface for accessing external OTP storage.
//!
//! This module provides userspace access to the ExternalOTP peripheral, which
//! models SoC-specific immutable storage external to Caliptra's built-in OTP
//! controller. Storage is organized into partitions, each with a defined size.
//!
//! Flash-accessing operations (`read`, `write`, `lock_partition`,
//! `is_partition_locked`) are asynchronous: the command starts the operation
//! and the result is delivered via an upcall/future.
//!
//! Metadata queries (`partition_count`, `partition_size`) are synchronous.

use crate::DefaultSyscalls;
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use caliptra_mcu_libtockasync::TockSubscribe;
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

mod subscribe {
    /// Operation-complete upcall.
    pub const OPERATION_DONE: u32 = 0;
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
    ///
    /// This is asynchronous: the command starts a flash read and the result
    /// is delivered via upcall.
    pub async fn read(&self, partition_id: u32, offset: u32) -> Result<u32, ErrorCode> {
        S::command(self.driver_num, cmd::SET_PARTITION, partition_id, 0)
            .to_result::<(), ErrorCode>()?;

        let mut sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::OPERATION_DONE);

        match S::command(self.driver_num, cmd::READ, offset, 0).to_result::<(), ErrorCode>() {
            Ok(()) => {}
            Err(e) => {
                sub.cancel();
                return Err(e);
            }
        }

        let (status, value, _) = TockSubscribe::subscribe_finish(sub).await?;
        if status == 0 {
            Ok(value)
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Write a u32 to a partition at the given byte offset.
    pub async fn write(&self, partition_id: u32, offset: u32, value: u32) -> Result<(), ErrorCode> {
        S::command(self.driver_num, cmd::SET_PARTITION, partition_id, 0)
            .to_result::<(), ErrorCode>()?;

        let mut sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::OPERATION_DONE);

        match S::command(self.driver_num, cmd::WRITE, offset, value).to_result::<(), ErrorCode>() {
            Ok(()) => {}
            Err(e) => {
                sub.cancel();
                return Err(e);
            }
        }

        let (status, _, _) = TockSubscribe::subscribe_finish(sub).await?;
        if status == 0 {
            Ok(())
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Lock a partition, preventing further writes.
    pub async fn lock_partition(&self, partition_id: u32) -> Result<(), ErrorCode> {
        let mut sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::OPERATION_DONE);

        match S::command(self.driver_num, cmd::LOCK_PARTITION, partition_id, 0)
            .to_result::<(), ErrorCode>()
        {
            Ok(()) => {}
            Err(e) => {
                sub.cancel();
                return Err(e);
            }
        }

        let (status, _, _) = TockSubscribe::subscribe_finish(sub).await?;
        if status == 0 {
            Ok(())
        } else {
            Err(ErrorCode::Fail)
        }
    }

    /// Check whether a partition is locked.
    pub async fn is_partition_locked(&self, partition_id: u32) -> Result<bool, ErrorCode> {
        let mut sub = TockSubscribe::subscribe::<S>(self.driver_num, subscribe::OPERATION_DONE);

        match S::command(self.driver_num, cmd::IS_PARTITION_LOCKED, partition_id, 0)
            .to_result::<(), ErrorCode>()
        {
            Ok(()) => {}
            Err(e) => {
                sub.cancel();
                return Err(e);
            }
        }

        let (status, value, _) = TockSubscribe::subscribe_finish(sub).await?;
        if status == 0 {
            Ok(value != 0)
        } else {
            Err(ErrorCode::Fail)
        }
    }
}
