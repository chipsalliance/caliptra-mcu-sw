// Licensed under the Apache-2.0 license.

use core::fmt::Write;
use mcu_rom_common::{FatalErrorHandler, RomEnv};
use romtime::{Exit, HexWord};

pub(crate) struct EmulatorWriter {}
pub(crate) static mut EMULATOR_WRITER: EmulatorWriter = EmulatorWriter {};

impl Write for EmulatorWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print_to_console(s);
        Ok(())
    }
}

pub(crate) fn print_to_console(buf: &str) {
    for b in buf.bytes() {
        // Print to this address for emulator output
        unsafe {
            core::ptr::write_volatile(0x1000_1041 as *mut u8, b);
        }
    }
}

pub(crate) struct EmulatorFatalErrorHandler {}
pub(crate) static mut FATAL_ERROR_HANDLER: EmulatorFatalErrorHandler = EmulatorFatalErrorHandler {};
impl FatalErrorHandler for EmulatorFatalErrorHandler {
    fn fatal_error(&mut self, code: u32) -> ! {
        let _ = writeln!(EmulatorWriter {}, "MCU fatal error: {}", HexWord(code));
        RomEnv::new().mci.set_fw_fatal_error(code);
        exit_emulator(code);
    }
}

pub(crate) struct EmulatorExiter {}
pub(crate) static mut EMULATOR_EXITER: EmulatorExiter = EmulatorExiter {};
impl Exit for EmulatorExiter {
    fn exit(&mut self, code: u32) {
        let _ = writeln!(EmulatorWriter {}, "MCU exit code: {}", HexWord(code));
        exit_emulator(code);
    }
}

/// Exit the emulator
pub fn exit_emulator(exit_code: u32) -> ! {
    // Safety: This is a safe memory address to write to for exiting the emulator.
    unsafe {
        // By writing to this address we can exit the emulator.
        core::ptr::write_volatile(0x1000_2000 as *mut u32, exit_code);
    }
    loop {}
}
