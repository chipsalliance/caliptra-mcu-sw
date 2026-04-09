//! This crate contains tests for `caliptra_mcu_libtock_platform` functionality that use the
//! `Syscalls` implementation.
//!
//! These tests are not in `caliptra_mcu_libtock_platform` because adding them to
//! `caliptra_mcu_libtock_platform causes two incompatible copies of `caliptra_mcu_libtock_platform` to be
//! compiled:
//!   1. The `caliptra_mcu_libtock_platform` with `cfg(test)` enabled
//!   2. The `caliptra_mcu_libtock_platform` that `caliptra_mcu_libtock_unittest` depends on, which has
//!      `cfg(test)` disabled.
//!
//! Mixing types from the two `caliptra_mcu_libtock_platform` instantiations in tests results
//! in confusing error messages, so instead those tests live in this crate.

#[cfg(test)]
mod allow_ro;

#[cfg(test)]
mod allow_rw;

#[cfg(test)]
mod command_tests;

#[cfg(test)]
mod exit_on_drop;

// TODO: Add Exit.

#[cfg(test)]
mod memop_tests;

#[cfg(test)]
mod subscribe_tests;

#[cfg(test)]
mod yield_tests;
