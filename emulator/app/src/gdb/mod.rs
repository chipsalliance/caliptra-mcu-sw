/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains gdb module for Caliptra Emulator.

--*/
pub mod gdb_state;
pub mod gdb_target;

pub use gdb_state::{wait_for_gdb_run, ControlledGdbServer};
pub use gdb_target::{ExecMode, GdbStopReason, GdbTarget};
