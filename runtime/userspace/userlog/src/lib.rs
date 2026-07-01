// Licensed under the Apache-2.0 license

//! MCU userspace logging API and optional defmt transport.

#![cfg_attr(target_arch = "riscv32", no_std)]
#![allow(static_mut_refs)]

mod fmt;
mod macros;

pub use fmt::{Bytes, Dbg, Hex32};

#[cfg(feature = "defmt-transport")]
pub use defmt;

/// Largest single defmt frame staged/drained, in bytes. Matches the kernel
/// flash-log per-entry scratch; frames larger than this are dropped whole.
#[cfg(feature = "defmt-transport")]
pub(crate) const FRAME_MAX: usize = 256;

#[cfg(feature = "defmt-transport")]
mod drain;
#[cfg(feature = "defmt-transport")]
mod logger;
#[cfg(feature = "defmt-transport")]
mod ring;

#[cfg(feature = "defmt-transport")]
pub use drain::drain_task;
#[cfg(feature = "defmt-transport")]
pub use logger::dropped;
