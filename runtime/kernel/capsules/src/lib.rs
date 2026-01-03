// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![forbid(unsafe_code)]

pub mod test;

pub mod doe;
pub mod flash_partition;
pub mod mailbox;
pub mod mbox_sram;
pub mod mci;
pub mod mctp;
pub mod mcu_mbox;
pub mod system;
