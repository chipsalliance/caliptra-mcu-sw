// Licensed under the Apache-2.0 license

//! Emulator-specific ExternalOTP driver implementation.
//!
//! Stores OTP partition data in External SRAM (accessible via DMA). The write-once
//! bitmap is kept in a kernel-local buffer since it needs byte-granularity access
//! that DMA (which operates on larger transfers) would be awkward for.
//!
//! **Integrators**: Replace this with your platform's actual OTP/EPROM driver.

#![cfg_attr(target_arch = "riscv32", no_std)]

pub mod ext_sram_otp;
