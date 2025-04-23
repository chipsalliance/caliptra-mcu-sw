//! `libtock_runtime` provides the runtime for Tock process binaries written in
//! Rust as well as interfaces to Tock's system calls.

#![no_std]
#![warn(unsafe_op_in_unsafe_fn)]

pub mod startup;

/// TockSyscalls implements `libtock_platform::Syscalls`.
pub struct TockSyscalls;

#[cfg(not(target_arch = "riscv32"))]
mod syscalls_impl_host;
#[cfg(target_arch = "riscv32")]
mod syscalls_impl_riscv;
