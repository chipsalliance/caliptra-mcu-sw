// Licensed under the Apache-2.0 license.

use core::fmt::Write;

use mcu_rom_common::FatalErrorHandler;
use romtime::HexWord;

pub(crate) struct FpgaWriter {}
pub(crate) static mut FPGA_WRITER: FpgaWriter = FpgaWriter {};

impl Write for FpgaWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print_to_console(s);
        Ok(())
    }
}

pub(crate) fn print_to_console(buf: &str) {
    for b in buf.bytes() {
        // Print to this address for FPGA output
        unsafe {
            core::ptr::write_volatile(0xa401_1014 as *mut u32, b as u32 | 0x100);
        }
    }
}

pub(crate) struct EmulatorFatalErrorHandler {}
pub(crate) static mut FATAL_ERROR_HANDLER: EmulatorFatalErrorHandler = EmulatorFatalErrorHandler {};
impl FatalErrorHandler for EmulatorFatalErrorHandler {
    fn fatal_error(&mut self, code: u32) -> ! {
        let _ = writeln!(FpgaWriter {}, "MCU fatal error: {}", HexWord(code));
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
