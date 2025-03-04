/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Peripheral library.

--*/
mod emu_ctrl;
mod flash_ctrl;
mod i3c;
pub(crate) mod i3c_protocol;
mod mci;
mod otp;
mod otp_digest;
mod root_bus;
mod spi_flash;
mod spi_host;
mod uart;

pub use emu_ctrl::EmuCtrl;
pub use flash_ctrl::DummyFlashCtrl;
pub use i3c::I3c;
pub use i3c_protocol::*;
pub use mci::Mci;
pub use otp::Otp;
pub use root_bus::{CaliptraRootBus, CaliptraRootBusArgs};
pub use spi_flash::IoMode;
pub use uart::Uart;
