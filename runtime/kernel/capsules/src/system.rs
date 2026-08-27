// Licensed under the Apache-2.0 license

//! This provides the capsule for Platform specific system utilities.

use core::cell::RefCell;

use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

pub const DRIVER_NUM: usize = 0xC000_0000;

mod cmd {
    pub const EXIT: u32 = 1;
    pub const GET_FIRMWARE_BOOT_TYPE: u32 = 2;
    pub const GET_MCU_ROM_CAPABILITIES: u32 = 3;
}

pub struct System<'a, E: caliptra_mcu_romtime::Exit> {
    exiter: RefCell<&'a mut E>,
}

impl<'a, E: caliptra_mcu_romtime::Exit> System<'a, E> {
    pub fn new(exiter: &'a mut E) -> System<'a, E> {
        System {
            exiter: RefCell::new(exiter),
        }
    }
}

/// Provide an interface for userland.
impl<E: caliptra_mcu_romtime::Exit> SyscallDriver for System<'_, E> {
    fn command(
        &self,
        cmd: usize,
        arg1: usize,
        _arg2: usize,
        _processid: ProcessId,
    ) -> CommandReturn {
        match cmd as u32 {
            cmd::EXIT => {
                self.exiter.borrow_mut().exit(arg1 as u32);
                CommandReturn::success()
            }
            cmd::GET_FIRMWARE_BOOT_TYPE => {
                match caliptra_mcu_romtime::handoff::get_firmware_boot_type() {
                    Ok(boot_type) => CommandReturn::success_u32(boot_type as u32),
                    Err(caliptra_mcu_romtime::handoff::FirmwareBootTypeReadError::Unsupported) => {
                        CommandReturn::failure(ErrorCode::NOSUPPORT)
                    }
                    Err(caliptra_mcu_romtime::handoff::FirmwareBootTypeReadError::Invalid) => {
                        CommandReturn::failure(ErrorCode::INVAL)
                    }
                }
            }
            cmd::GET_MCU_ROM_CAPABILITIES => {
                match caliptra_mcu_romtime::handoff::get_mcu_rom_capabilities() {
                    Some(capabilities) => CommandReturn::success_u32(capabilities.bits()),
                    None => CommandReturn::failure(ErrorCode::NOSUPPORT),
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, _processid: ProcessId) -> Result<(), kernel::process::Error> {
        Ok(())
    }
}
