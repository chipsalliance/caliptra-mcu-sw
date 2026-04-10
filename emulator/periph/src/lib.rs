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
pub mod ecc_ram;
mod emu_ctrl;
mod flash_ctrl;
mod i3c;
pub(crate) mod i3c_protocol;
mod lc_ctrl;
mod mci;
mod mcu_mbox0;
mod otp;
pub use caliptra_mcu_otp_digest::{
    caliptra_mcu_otp_digest, otp_scramble, otp_unscramble, OTP_SCRAMBLE_KEYS,
};
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
pub use otp::{Otp, OtpArgs};
pub use reset_reason::ResetReasonEmulator;
pub use root_bus::{McuRootBus, McuRootBusArgs, McuRootBusOffsets};
pub use uart::Uart;

/// Stub I3C1 peripheral backed by generated register defaults so that
/// firmware accesses to the i3c1 address range see realistic reset
/// values (e.g. TTI capability bits) instead of causing a bus fault.
pub struct StubI3c1(caliptra_mcu_emulator_registers_generated::i3c1::I3c1Generated);

impl StubI3c1 {
    pub fn new() -> Self {
        Self(caliptra_mcu_emulator_registers_generated::i3c1::I3c1Generated::default())
    }
}

impl Default for StubI3c1 {
    fn default() -> Self {
        Self::new()
    }
}

impl caliptra_mcu_emulator_registers_generated::i3c1::I3c1Peripheral for StubI3c1 {
    fn generated(
        &mut self,
    ) -> Option<&mut caliptra_mcu_emulator_registers_generated::i3c1::I3c1Generated> {
        Some(&mut self.0)
    }
}
