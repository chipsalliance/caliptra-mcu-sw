// Licensed under the Apache-2.0 license
#![cfg_attr(target_arch = "riscv32", no_std)]

// Helpers to handle writing to the emulator UART output.

pub struct EmulatorWriter {}
pub static mut WRITER: EmulatorWriter = EmulatorWriter {};

impl core::fmt::Write for EmulatorWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print_to_console(s);
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        let _ = write!(unsafe { &mut $crate::WRITER }, $($arg)*);
    };
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {
        let _ = writeln!(unsafe { &mut $crate::WRITER }, $($arg)*);
    };
}

pub(crate) fn print_to_console(buf: &str) {
    for b in buf.bytes() {
        // Print to this address for emulator output
        unsafe {
            core::ptr::write_volatile(0x2000_1041 as *mut u8, b);
        }
    }
}
