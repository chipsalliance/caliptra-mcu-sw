// Licensed under the Apache-2.0 license

#![no_std]

pub mod dma;
pub mod doe;
pub mod flash;
pub mod logging;
pub mod mailbox;
pub mod mbox_sram;
pub mod mci;
pub mod mctp;
pub mod mcu_mbox;
pub mod system;

#[cfg(target_arch = "riscv32")]
pub type DefaultSyscalls = libtock_runtime::TockSyscalls;

#[cfg(not(target_arch = "riscv32"))]
pub type DefaultSyscalls = libtock_unittest::fake::Syscalls;
