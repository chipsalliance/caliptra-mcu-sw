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
//! * [`alloc`] — The [`SpdmPalAlloc`] impl that hands out
//!   [`ScratchBox`] / [`BitmapBytes`] from a caller-supplied scratch
//!   region. The pool itself lives in [`caliptra_mcu_scratch_alloc`].
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
//! * The whole [`pal`] surface is re-exported at the crate root so
//!   consumers write `use caliptra_mcu_spdm_pal::*`.
//! * [`caliptra_mcu_spdm_codec`] is re-exported as [`codec`] so the stack
//!   and downstream code share one wire-codec version.
//! * The scratch-pool types are deliberately *not* re-exported — see the
//!   note on the private import below.

#![no_std]

mod alloc;
pub mod cert;
mod hash;
mod io;
pub mod measurements;
mod pal;
mod session_crypto;

pub use measurements::MeasurementProvider;
pub use pal::*;

pub use caliptra_mcu_spdm_codec as codec;

use caliptra_mcu_spdm_traits::*;

// Pool types are referenced throughout this crate's modules (which pull them
// in via `use super::*`), but are intentionally not re-exported: non-SPDM
// tasks must depend on `caliptra-mcu-scratch-alloc` directly rather than
// reaching for the allocator through the SPDM PAL.
use caliptra_mcu_scratch_alloc::*;
