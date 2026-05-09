// Licensed under the Apache-2.0 license.

use core::fmt::Write;

use mcu_rom_common::{FatalErrorHandler, RomEnv};
use romtime::{Exit, HexWord};

pub(crate) struct FpgaWriter {}
pub(crate) static mut FPGA_WRITER: FpgaWriter = FpgaWriter {};

const FPGA_UART_OUTPUT: *mut u32 = 0xa401_1014 as *mut u32;

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
            core::ptr::write_volatile(FPGA_UART_OUTPUT, b as u32 | 0x100);
        }
    }
}

pub(crate) struct FpgaFatalErrorHandler {}
pub(crate) static mut FATAL_ERROR_HANDLER: FpgaFatalErrorHandler = FpgaFatalErrorHandler {};
impl FatalErrorHandler for FpgaFatalErrorHandler {
    fn fatal_error(&mut self, code: u32) -> ! {
        let _ = writeln!(FpgaWriter {}, "MCU fatal error: {}", HexWord(code));
        RomEnv::new().mci.set_fw_fatal_error(code);
        exit_fpga(code);
    }
}

/// Exit the FPGA
pub fn exit_fpga(exit_code: u32) -> ! {
    // Safety: This is a safe memory address to write to for exiting the FPGA.
    unsafe {
        // By writing to this address we can exit the FPGA.
        let b = if exit_code == 0 { 0xff } else { 0x01 };
        core::ptr::write_volatile(FPGA_UART_OUTPUT, b as u32 | 0x100);
    }
    loop {}
}

pub struct Exiter {}

impl Exit for Exiter {
    fn exit(&mut self, code: u32) {
        exit_fpga(code);
    }
}

pub(crate) static mut EXITER: Exiter = Exiter {};
