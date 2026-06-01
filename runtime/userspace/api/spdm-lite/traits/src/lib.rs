// Licensed under the Apache-2.0 license

//! `mcu-spdm-lite-traits` — Core trait definitions for the SPDM-Lite stack.
//!
//! This crate provides the foundational abstractions used by the SPDM-Lite
//! implementation. It is intentionally kept minimal and dependency-free
//! (beyond `core`) so that platform-specific implementations can depend on
//! it without pulling in the full stack.
//!
//! # Modules
//!
//! * [`io`] — Transport I/O traits and message-kind discriminator
//!   ([`SpdmPalIo`], [`SpdmPalIoTransport`], [`SpdmPalIoKind`]).
//! * [`pal`] — Platform Abstraction Layer traits for platform-specific
//!   cryptographic and hardware operations.
//! * [`transport`] — Byte-oriented PAL transport trait.
//!
//! Error type: this crate uses [`mcu_error::McuErrorCode`] directly via
//! the re-exports below. There is no SPDM-specific error alias —
//! every runtime userspace API shares one error type.
#![no_std]
#![allow(async_fn_in_trait)]

mod alloc;
mod cert;
mod hash;
mod io;
mod measurements;
mod pal;
mod transport;

pub use alloc::*;
pub use cert::*;
pub use hash::*;
pub use io::*;
pub use measurements::*;
pub use pal::*;
pub use transport::*;

// Re-export the workspace-wide error type/alias for convenience: users
// of this crate get them transitively without needing `mcu-error` as a
// direct dependency.
pub use mcu_error::{McuErrorCode, McuResult};
