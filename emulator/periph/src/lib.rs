/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Peripheral library.

--*/

mod axicdma;
mod caliptra_to_ext_bus;
mod doe_mbox;
mod emu_ctrl;
mod flash_ctrl;
mod i3c;
pub(crate) mod i3c_protocol;
mod lc_ctrl;
mod mci;
mod mcu_mbox0;
mod network_root_bus;
mod otp;
mod otp_digest;
mod reset_reason;
mod root_bus;
mod uart;

pub use axicdma::AxiCDMA;
pub use caliptra_to_ext_bus::CaliptraToExtBus;
pub use doe_mbox::{DoeMboxPeriph, DummyDoeMbox};
pub use emu_ctrl::EmuCtrl;
pub use flash_ctrl::DummyFlashCtrl;
pub use i3c::I3c;
pub use i3c_protocol::*;
pub use lc_ctrl::LcCtrl;
pub use mci::Mci;
pub use mcu_mbox0::{MciMailboxRequester, McuMailbox0External, McuMailbox0Internal};
pub use network_root_bus::{NetworkRootBus, NetworkRootBusArgs, NetworkRootBusOffsets};
pub use otp::{Otp, OtpArgs};
pub use otp_digest::{otp_digest, otp_scramble, otp_unscramble};
pub use reset_reason::ResetReasonEmulator;
pub use root_bus::{McuRootBus, McuRootBusArgs, McuRootBusOffsets};
pub use uart::Uart;
