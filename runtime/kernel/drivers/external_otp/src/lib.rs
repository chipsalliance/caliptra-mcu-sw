// Licensed under the Apache-2.0 license

//! ExternalOTP driver: Hardware Interface Layer trait.
//!
//! This crate defines the platform-agnostic interface for an external OTP
//! peripheral that provides partition-based immutable storage outside Caliptra's
//! built-in OTP controller. Platform-specific implementations (e.g. memory-backed,
//! flash-backed, fuse controller) live in their respective platform crates.

#![cfg_attr(target_arch = "riscv32", no_std)]

pub mod hil;
