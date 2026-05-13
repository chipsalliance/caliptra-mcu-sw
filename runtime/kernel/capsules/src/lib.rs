// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![forbid(unsafe_code)]

/// Error log — always compiled in. Use for failures that affect correctness.
#[macro_export]
macro_rules! capsule_error {
    ($prefix:literal, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        println!(concat!("[", $prefix, "] ERR: ", $fmt) $(, $arg)*)
    }};
}

/// Debug log — compiled out unless `debug-capsule-prints` feature is enabled.
#[macro_export]
macro_rules! capsule_debug {
    ($prefix:literal, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        #[cfg(feature = "debug-capsule-prints")]
        println!(concat!("[", $prefix, "] DBG: ", $fmt) $(, $arg)*)
    }};
}

pub mod test;

pub mod caliptra;
pub mod doe;
pub mod flash_partition;
pub mod mailbox;
pub mod mbox_sram;
pub mod mci;
pub mod mctp;
pub mod mcu_mbox;
pub mod otp;
pub mod system;
