// Licensed under the Apache-2.0 license

//! `caliptra-mcu-spdm-pal` — MCU-side Platform Abstraction Layer for the
//! SPDM-Lite stack.
//!
//! This crate provides the concrete implementations of the
//! [`SpdmPal`](caliptra_mcu_spdm_traits::SpdmPal) super-trait family
//! (allocation, hashing, framed I/O) that the
//! [`caliptra-mcu-spdm-stack`](../../stack) consumes as its single point
//! of platform binding.
//!
//! # Modules
//!
//! * [`alloc`] — Bitmap allocator and the [`SpdmPalAlloc`] impl
//!   that hands out [`McuSpdmBox`] / [`BitmapBytes`] from a
//!   caller-supplied scratch region.
//! * [`hash`] — [`SpdmPalHash`] impl and the running-hash bridge
//!   into [`mcu_caliptra_api_lite`].
//! * [`io`] — [`SpdmPalIo`] / [`SpdmPalIoTransport`] impls bridging
//!   the higher-level framed-message API onto the byte-oriented
//!   [`SpdmPalTransport`](caliptra_mcu_spdm_traits::SpdmPalTransport).
//! * [`pal`] — The [`McuSpdmPal`] aggregate that ties allocator,
//!   hash, and transport together.
//!
//! # Re-exports
//!
//! * The whole [`alloc`] / [`pal`] surface is re-exported at the
//!   crate root so consumers write `use caliptra_mcu_spdm_pal::*`.
//! * [`caliptra_mcu_spdm_codec`] is re-exported as [`codec`] so the stack
//!   and downstream code share one wire-codec version.

#![no_std]

mod alloc;
pub mod cert;
pub mod errors;
mod hash;
mod io;
pub mod measurements;
mod pal;
mod session_crypto;

pub use self::alloc::*;
pub use measurements::MeasurementProvider;
pub use pal::*;

pub use caliptra_mcu_spdm_codec as codec;

use caliptra_mcu_spdm_traits::*;
