// Licensed under the Apache-2.0 license

#![no_std]

pub mod dma;
pub mod doe;
pub mod flash;
pub mod mailbox;
pub mod mctp;

#[cfg(target_arch = "riscv32")]
pub type DefaultSyscalls = libtock_runtime::TockSyscalls;

#[cfg(not(target_arch = "riscv32"))]
pub type DefaultSyscalls = libtock_unittest::fake::Syscalls;
