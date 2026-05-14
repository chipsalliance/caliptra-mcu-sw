// Licensed under the Apache-2.0 license

//! ExternalOTP capsule: exposes the ExternalOtp HIL trait to userspace via syscalls.
//!
//! This capsule provides partition-based OTP read/write access to userspace
//! applications. Each read or write operates on a single u32 (4 bytes).

use caliptra_mcu_external_otp_driver::hil::ExternalOtp;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::syscall::{CommandReturn, SyscallDriver};
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

#[derive(Default)]
pub struct App {
    active_partition: u32,
}

pub struct ExternalOtpCapsule<'a> {
    driver: &'a dyn ExternalOtp,
    apps: Grant<App, UpcallCount<0>, AllowRoCount<0>, AllowRwCount<0>>,
}

impl<'a> ExternalOtpCapsule<'a> {
    pub fn new(
        driver: &'a dyn ExternalOtp,
        grant: Grant<App, UpcallCount<0>, AllowRoCount<0>, AllowRwCount<0>>,
    ) -> Self {
        Self {
            driver,
            apps: grant,
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
                let offset = r2 as u32;
                let result = self.apps.enter(processid, |app, _| {
                    self.driver.read(app.active_partition, offset)
                });
                match result {
                    Ok(Ok(value)) => CommandReturn::success_u32(value),
                    Ok(Err(e)) => CommandReturn::failure(ErrorCode::from(e)),
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            cmd::WRITE => {
                let offset = r2 as u32;
                let value = r3 as u32;
                let result = self.apps.enter(processid, |app, _| {
                    self.driver.write(app.active_partition, offset, value)
                });
                match result {
                    Ok(Ok(())) => CommandReturn::success(),
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
                let partition_id = r2 as u32;
                match self.driver.lock_partition(partition_id) {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(ErrorCode::from(e)),
                }
            }

            cmd::IS_PARTITION_LOCKED => {
                let partition_id = r2 as u32;
                match self.driver.is_partition_locked(partition_id) {
                    Ok(locked) => CommandReturn::success_u32(locked as u32),
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
