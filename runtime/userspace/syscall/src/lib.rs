// Licensed under the Apache-2.0 license

#![no_std]

pub mod caliptra;
pub mod dma;
pub mod doe;
pub mod external_otp;
pub mod flash;
pub mod logging;
pub mod mailbox;
pub mod mbox_sram;
pub mod mci;
pub mod mctp;
pub mod mcu_mbox;
pub mod otp;
pub mod system;

#[cfg(target_arch = "riscv32")]
pub type DefaultSyscalls = caliptra_mcu_libtock_runtime::TockSyscalls;

#[cfg(not(target_arch = "riscv32"))]
pub type DefaultSyscalls = caliptra_mcu_libtock_unittest::fake::Syscalls;

/// `writeln!` to a `core::fmt::Write` sink that is stripped in `release` builds.
///
/// In default (devel) builds expands to `let _ = ::core::writeln!($($arg)*);`.
/// With this crate's `feature = "release"` the expansion is a never-called
/// closure so the format arguments are still type-checked but LTO +
/// `--gc-sections` drop the format strings, any `Debug`/`Display` impls
/// reached via `{:?}`/`{}`, and the Tock console syscall path from the
/// linked binary.
///
/// The cfg is evaluated when this crate is built, so consumers do not need a
/// `release` feature of their own — they only need to import the macro.
#[cfg(not(feature = "release"))]
#[macro_export]
macro_rules! console_writeln {
    ($($arg:tt)*) => {{
        let _ = ::core::writeln!($($arg)*);
    }};
}

#[cfg(feature = "release")]
#[macro_export]
macro_rules! console_writeln {
    ($($arg:tt)*) => {{
        let _ = || -> ::core::fmt::Result { ::core::writeln!($($arg)*) };
    }};
}
