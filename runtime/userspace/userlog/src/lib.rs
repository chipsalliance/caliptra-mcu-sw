// Licensed under the Apache-2.0 license

//! defmt-based userspace logging for the Caliptra MCU.
//!
//! The `#[defmt::global_logger]` stages frames; [`drain_task`] ships them to the
//! flash log capsule. Spawn [`drain_task`] once from the userspace executor.

#![cfg_attr(target_arch = "riscv32", no_std)]
#![allow(static_mut_refs)]

/// Largest single defmt frame staged/drained, in bytes. Matches the kernel
/// flash-log per-entry scratch; frames larger than this are dropped whole.
pub(crate) const FRAME_MAX: usize = 256;

mod drain;
mod logger;
mod ring;

pub use drain::drain_task;
pub use logger::dropped;
