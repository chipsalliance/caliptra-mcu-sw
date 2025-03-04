// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

mod error;
pub use error::*;
mod static_ref;
pub use static_ref::*;

use core::fmt::{Display, Write};

pub static mut WRITER: Option<&'static mut dyn Write> = None;

/// Sets the global backing writer for `print` and `println` macros.
pub fn set_printer(writer: &'static mut dyn Write) {
    unsafe {
        WRITER = Some(writer);
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        unsafe {
            if let Some(writer) = $crate::WRITER.as_mut() {
                let _ = write!(writer, $($arg)*);
            }
        }
    };
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {
        unsafe {
            if let Some(writer) = $crate::WRITER.as_mut() {
                let _ = writeln!(writer, $($arg)*);
            }
        }
    };
}

pub struct HexBytes<'a>(pub &'a [u8]);
impl Display for HexBytes<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Rust can't prove the indexes are correct in a format macro.
        for &x in self.0.iter() {
            let c = x >> 4;
            if c < 10 {
                f.write_char((c + b'0') as char)?;
            } else {
                f.write_char((c - 10 + b'A') as char)?;
            }
            let c = x & 0xf;
            if c < 10 {
                f.write_char((c + b'0') as char)?;
            } else {
                f.write_char((c - 10 + b'A') as char)?;
            }
        }
        Ok(())
    }
}

pub struct HexWord(pub u32);
impl Display for HexWord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        HexBytes(&self.0.to_be_bytes()).fmt(f)
    }
}
