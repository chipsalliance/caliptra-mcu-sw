/*++

Licensed under the Apache-2.0 license.

File Name:

    rom_env.rs

Abstract:

    ROM Environment - Encapsulates all peripherals and managers used by ROM

--*/

use crate::Soc;
use core::ptr::addr_of;
use registers_generated::{i3c, lc_ctrl, mci, otp_ctrl, soc};
use romtime::{CaliptraSoC, Mci, StaticRef};
use romtime::{Lifecycle, Otp};

/// ROM Environment containing all peripherals and managers
pub struct RomEnv {
    pub mci: Mci,
    pub soc: Soc,
    pub lc: Lifecycle,
    pub otp: Otp,
    pub i3c: crate::i3c::I3c,
    pub i3c_base: StaticRef<i3c::regs::I3c>,
    pub soc_manager: CaliptraSoC,
    pub straps: StaticRef<mcu_config::McuStraps>,
}

impl RomEnv {
    /// Create a new ROM environment with all peripherals initialized
    pub fn new() -> Self {
        // Get straps
        let straps: StaticRef<mcu_config::McuStraps> =
            unsafe { StaticRef::new(addr_of!(crate::MCU_STRAPS)) };

        // Get base addresses from MCU memory map
        unsafe {
            let lc_base: StaticRef<lc_ctrl::regs::LcCtrl> =
                StaticRef::new(crate::MCU_MEMORY_MAP.lc_offset as *const lc_ctrl::regs::LcCtrl);
            let otp_base: StaticRef<otp_ctrl::regs::OtpCtrl> =
                StaticRef::new(crate::MCU_MEMORY_MAP.otp_offset as *const otp_ctrl::regs::OtpCtrl);
            let i3c_base: StaticRef<i3c::regs::I3c> =
                StaticRef::new(crate::MCU_MEMORY_MAP.i3c_offset as *const i3c::regs::I3c);
            let soc_base: StaticRef<soc::regs::Soc> =
                StaticRef::new(crate::MCU_MEMORY_MAP.soc_offset as *const soc::regs::Soc);
            let mci_base: StaticRef<mci::regs::Mci> =
                StaticRef::new(crate::MCU_MEMORY_MAP.mci_offset as *const mci::regs::Mci);

            // Create SoC manager
            let soc_manager = CaliptraSoC::new(
                Some(crate::MCU_MEMORY_MAP.soc_offset),
                Some(crate::MCU_MEMORY_MAP.soc_offset),
                Some(crate::MCU_MEMORY_MAP.mbox_offset),
            );

            // Create peripherals
            let soc = Soc::new(soc_base);
            let mci = Mci::new(mci_base);
            let lc = Lifecycle::new(lc_base);
            let otp = Otp::new(otp_base);
            let i3c = crate::i3c::I3c::new(i3c_base);

            Self {
                mci,
                soc,
                lc,
                otp,
                i3c,
                i3c_base,
                soc_manager,
                straps,
            }
        }
    }
}

impl Default for RomEnv {
    fn default() -> Self {
        Self::new()
    }
}
