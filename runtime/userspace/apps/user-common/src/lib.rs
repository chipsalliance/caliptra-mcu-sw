// Licensed under the Apache-2.0 license

//! Common platform-agnostic code shared between emulator and FPGA user apps.

#![cfg_attr(target_arch = "riscv32", no_std)]
#![allow(static_mut_refs)]

pub mod image_loader;
pub mod mcu_mbox;
pub mod soc_env;
pub mod spdm;
pub mod vdm;
