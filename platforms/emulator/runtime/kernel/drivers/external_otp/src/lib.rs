// Licensed under the Apache-2.0 license

//! Emulator-specific ExternalOTP driver implementation.
//!
//! Stores OTP partition data in flash via the kernel's async flash driver
//! stack, routed through the flash mux to avoid register conflicts.
//!
//! **Integrators**: Replace this with your platform's actual OTP/EPROM driver.

#![cfg_attr(target_arch = "riscv32", no_std)]

pub mod ext_flash_otp;
