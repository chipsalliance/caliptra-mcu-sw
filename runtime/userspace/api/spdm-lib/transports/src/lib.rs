// Licensed under the Apache-2.0 license

//! `caliptra-mcu-spdm-transports` — Concrete SPDM-Lite PAL transport
//! implementations for MCU userspace.
//!
//! This crate provides ready-to-use implementations of the
//! [`SpdmPalTransport`](caliptra_mcu_spdm_traits::SpdmPalTransport) trait
//! over MCU platform transports.

#![no_std]

pub mod doe;
pub mod errors;
pub mod mctp;

pub use doe::McuSpdmDoeTransport;
pub use mctp::McuSpdmMctpTransport;
