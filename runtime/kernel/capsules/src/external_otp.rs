// Licensed under the Apache-2.0 license

//! ExternalOTP capsule: exposes the async ExternalOtp HIL to userspace via syscalls.
//!
//! Flash-accessing operations (read, write, lock, is_partition_locked) are
//! asynchronous: the command starts the operation and a completion upcall
//! delivers the result. Metadata queries (partition_count, partition_size)
//! remain synchronous.
//!
//! ## Upcall format
//!
//! Upcall 0 (`OPERATION_DONE`): `(status, value, 0)`
//! - `status`: 0 on success, non-zero `ExternalOtpError` discriminant on failure.
//! - `value`: the u32 result for READ / IS_PARTITION_LOCKED; 0 for WRITE / LOCK.

use caliptra_mcu_external_otp_driver::hil::{ExternalOtp, ExternalOtpClient, ExternalOtpError};
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::OptionalCell;
use kernel::{ErrorCode, ProcessId};

/// Driver number for the ExternalOTP capsule.
pub const EXTERNAL_OTP_DRIVER_NUM: usize = 0xD100_0000;

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

mod upcall {
    /// Operation-complete callback.
    pub const OPERATION_DONE: usize = 0;
    pub const COUNT: u8 = 1;
}

/// Map ExternalOtpError to a non-zero status code for the upcall.
fn error_to_status(e: ExternalOtpError) -> u32 {
    match e {
        ExternalOtpError::WriteProtected => 1,
        ExternalOtpError::OutOfBounds => 2,
        ExternalOtpError::InvalidPartition => 3,
        ExternalOtpError::PartitionLocked => 4,
        ExternalOtpError::HardwareError => 5,
        ExternalOtpError::Busy => 6,
    }
}

#[derive(Default)]
pub struct App {
    active_partition: u32,
}

pub struct ExternalOtpCapsule<'a> {
    driver: &'a dyn ExternalOtp<'a>,
    apps: Grant<App, UpcallCount<{ upcall::COUNT }>, AllowRoCount<0>, AllowRwCount<0>>,
    /// The process that currently has an in-flight async operation.
    current_app: OptionalCell<ProcessId>,
}

impl<'a> ExternalOtpCapsule<'a> {
    pub fn new(
        driver: &'a dyn ExternalOtp<'a>,
        grant: Grant<App, UpcallCount<{ upcall::COUNT }>, AllowRoCount<0>, AllowRwCount<0>>,
    ) -> Self {
        Self {
            driver,
            apps: grant,
            current_app: OptionalCell::empty(),
        }
    }

    /// Schedule the completion upcall and clear `current_app`.
    fn complete_upcall(&self, status: u32, value: u32) {
        if let Some(processid) = self.current_app.take() {
            let _ = self.apps.enter(processid, |_app, kernel_data| {
                kernel_data
                    .schedule_upcall(upcall::OPERATION_DONE, (status as usize, value as usize, 0))
                    .ok();
            });
        }
    }
}

impl ExternalOtpClient for ExternalOtpCapsule<'_> {
    fn read_done(&self, result: Result<u32, ExternalOtpError>) {
        match result {
            Ok(value) => self.complete_upcall(0, value),
            Err(e) => self.complete_upcall(error_to_status(e), 0),
        }
    }

    fn write_done(&self, result: Result<(), ExternalOtpError>) {
        match result {
            Ok(()) => self.complete_upcall(0, 0),
            Err(e) => self.complete_upcall(error_to_status(e), 0),
        }
    }

    fn lock_done(&self, result: Result<(), ExternalOtpError>) {
        match result {
            Ok(()) => self.complete_upcall(0, 0),
            Err(e) => self.complete_upcall(error_to_status(e), 0),
        }
    }

    fn lock_check_done(&self, result: Result<bool, ExternalOtpError>) {
        match result {
            Ok(locked) => self.complete_upcall(0, locked as u32),
            Err(e) => self.complete_upcall(error_to_status(e), 0),
        }
    }
}

impl SyscallDriver for ExternalOtpCapsule<'_> {
    fn command(
        &self,
        command_num: usize,
        r2: usize,
        r3: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_num as u32 {
            cmd::EXISTS => CommandReturn::success(),

            cmd::SET_PARTITION => {
                let partition_id = r2 as u32;
                if self.driver.partition_info(partition_id).is_none() {
                    return CommandReturn::failure(ErrorCode::INVAL);
                }
                match self.apps.enter(processid, |app, _| {
                    app.active_partition = partition_id;
                }) {
                    Ok(()) => CommandReturn::success(),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::READ => {
                if self.current_app.is_some() {
                    return CommandReturn::failure(ErrorCode::BUSY);
                }
                let offset = r2 as u32;
                let result = self.apps.enter(processid, |app, _| {
                    self.driver.read(app.active_partition, offset)
                });
                match result {
                    Ok(Ok(())) => {
                        self.current_app.set(processid);
                        CommandReturn::success()
                    }
                    Ok(Err(e)) => CommandReturn::failure(ErrorCode::from(e)),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::WRITE => {
                if self.current_app.is_some() {
                    return CommandReturn::failure(ErrorCode::BUSY);
                }
                let offset = r2 as u32;
                let value = r3 as u32;
                let result = self.apps.enter(processid, |app, _| {
                    self.driver.write(app.active_partition, offset, value)
                });
                match result {
                    Ok(Ok(())) => {
                        self.current_app.set(processid);
                        CommandReturn::success()
                    }
                    Ok(Err(e)) => CommandReturn::failure(ErrorCode::from(e)),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::GET_PARTITION_SIZE => {
                let partition_id = r2 as u32;
                match self.driver.partition_info(partition_id) {
                    Some(info) => CommandReturn::success_u32(info.size),
                    None => CommandReturn::failure(ErrorCode::INVAL),
                }
            }

            cmd::GET_PARTITION_COUNT => {
                CommandReturn::success_u32(self.driver.partition_count() as u32)
            }

            cmd::LOCK_PARTITION => {
                if self.current_app.is_some() {
                    return CommandReturn::failure(ErrorCode::BUSY);
                }
                let partition_id = r2 as u32;
                match self.driver.lock_partition(partition_id) {
                    Ok(()) => {
                        self.current_app.set(processid);
                        CommandReturn::success()
                    }
                    Err(e) => CommandReturn::failure(ErrorCode::from(e)),
                }
            }

            cmd::IS_PARTITION_LOCKED => {
                if self.current_app.is_some() {
                    return CommandReturn::failure(ErrorCode::BUSY);
                }
                let partition_id = r2 as u32;
                match self.driver.is_partition_locked(partition_id) {
                    Ok(()) => {
                        self.current_app.set(processid);
                        CommandReturn::success()
                    }
                    Err(e) => CommandReturn::failure(ErrorCode::from(e)),
                }
            }

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
