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
pub mod i3c_socket;
pub mod mctp_transport;
pub mod tests;

pub use emulator::{Emulator, EmulatorArgs};

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub static MCU_RUNTIME_STARTED: AtomicBool = AtomicBool::new(false);
pub static EMULATOR_RUNNING: AtomicBool = AtomicBool::new(true);

pub fn wait_for_runtime_start() {
    while EMULATOR_RUNNING.load(Ordering::Relaxed) && !MCU_RUNTIME_STARTED.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(10));
    }
}
