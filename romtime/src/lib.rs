// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![allow(static_mut_refs)]

mod lifecycle;
pub use lifecycle::*;
mod mci;
pub use mci::*;
mod otp;
pub use otp::*;
mod soc_manager;
pub use soc_manager::*;
mod static_ref;
pub use static_ref::*;

// Helpers to handle writing to the emulator UART output.

use core::fmt::{Display, Write};

pub static mut WRITER: Option<&'static mut dyn Write> = None;
pub static mut EXITER: Option<&'static mut dyn Exit> = None;

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
        if let Some(writer) = unsafe { $crate::WRITER.as_mut() } {
            let _ = writeln!(writer, $($arg)*);
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

pub trait Exit {
    fn exit(&mut self, code: u32);
}

pub fn set_exiter(exiter: &'static mut dyn Exit) {
    unsafe {
        EXITER = Some(exiter);
    }
}

pub fn test_exit(code: u32) -> ! {
    unsafe {
        if let Some(exiter) = EXITER.as_mut() {
            exiter.exit(code);
        }
    }
    #[allow(clippy::empty_loop)]
    loop {}
}

#[cfg(not(target_arch = "riscv32"))]
pub fn crc8(crc: u8, data: u8) -> u8 {
    // CRC-8 with last 8 bits of polynomial x^8 + x^2 + x^1 + 1.
    let polynomial = 0x07;
    let mut crc = crc;
    crc ^= data;
    for _ in 0..8 {
        if crc & 0x80 != 0 {
            crc = (crc << 1) ^ polynomial;
        } else {
            crc <<= 1;
        }
    }
    crc
}

#[cfg(target_arch = "riscv32")]
pub fn crc8(crc: u8, data: u8) -> u8 {
    // CRC-8 with last 8 bits of polynomial x^8 + x^2 + x^1 + 1.
    let polynomial = 0x07;
    let crc = (crc ^ data) as usize;
    let a: usize;
    let b: usize;

    unsafe {
        core::arch::asm!(
            "clmul {a}, {crc}, {poly}",
            "srli {tmp}, {a}, 8",
            "clmul {b}, {tmp}, {poly}",
            crc = in(reg) crc,
            poly = in(reg) polynomial,
            a = out(reg) a,
            b = out(reg) b,
            tmp = out(reg) _,
        );
    }

    (a ^ b) as u8
}
