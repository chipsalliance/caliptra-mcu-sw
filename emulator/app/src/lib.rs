/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Library interface for the Caliptra MCU Emulator.

--*/

pub mod dis;
pub mod dis_test;
pub mod doe_mbox_fsm;
pub mod elf;
pub mod emulator;
pub mod gdb;
pub mod tests;

pub use emulator::{Emulator, EmulatorArgs, ExternalReadCallback, ExternalWriteCallback};
