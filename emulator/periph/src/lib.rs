/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Peripheral library.

--*/
extern crate arrayref;

mod emu_ctrl;
mod otp;
mod otp_digest;
mod root_bus;
mod uart;

pub use emu_ctrl::EmuCtrl;
pub use otp::Otp;
pub use root_bus::{CaliptraRootBus, CaliptraRootBusArgs};
pub use uart::Uart;