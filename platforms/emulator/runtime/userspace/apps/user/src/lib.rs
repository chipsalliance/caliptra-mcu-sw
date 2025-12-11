// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

pub const NAME: &str = "user-app";
pub const MINIMUM_RAM: u32 = 96 * 1024;
pub const STACK_SIZE: usize = 0xae00;
pub const PERMISSIONS: &[(u32, u32)] = &[];
