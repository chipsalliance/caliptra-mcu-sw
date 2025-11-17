/*++

Licensed under the Apache-2.0 license.

File Name:

    cold_boot.rs

Abstract:

    Cold Boot Flow - Handles initial boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

#[cfg(target_arch = "riscv32")]
use crate::MCU_MEMORY_MAP;
use crate::{fatal_error, BootFlow, RomEnv, RomParameters};
use caliptra_api::{mailbox::MailboxRespHeader, CaliptraApiError};
use core::fmt::Write;
use mcu_error::McuError;
use registers_generated::mci;
use romtime::HexWord;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

pub struct FwHitlessUpdate {}

impl BootFlow for FwHitlessUpdate {
    fn run(env: &mut RomEnv, _params: RomParameters) -> ! {
        romtime::println!("[mcu-rom] Starting fw hitless update flow");

        let mci = &env.mci;

        // Enable notif_cptra_mcu_reset_req_sts interrupt
        mci.registers
            .intr_block_rf_notif0_intr_en_r
            .modify(mci::bits::Notif0IntrEnT::NotifCptraMcuResetReqEn::SET);

        // Clear notif_cptra_mcu_reset_req_sts
        let is_fw_available = mci
            .registers
            .intr_block_rf_notif0_internal_intr_r
            .read(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts)
            != 0;
        mci.registers
            .intr_block_rf_notif0_internal_intr_r
            .modify(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts::SET);

        if is_fw_available {
            // Wait for Caliptra to clear FW_EXEC_CTRL[2]. This will generate another notif_cptra_mcu_reset_req_sts interrupt.
            loop {
                let notif_cptra_mcu_reset_req_sts = mci
                    .registers
                    .intr_block_rf_notif0_internal_intr_r
                    .read(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts);
                if notif_cptra_mcu_reset_req_sts != 0 {
                    mci.registers
                        .intr_block_rf_notif0_internal_intr_r
                        .write(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts::SET);
                    break;
                }
            }
        }

        // Clear notif_cptra_mcu_reset_req_sts interrupt
        mci.registers
            .intr_block_rf_notif0_internal_intr_r
            .modify(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts::SET);

        // Create local references to minimize code changes
        let soc_manager = &mut env.soc_manager;
        let soc = &env.soc;

        // Wait for Caliptra to assert FW_EXEC_CTRL[2]
        while !soc.fw_ready() {}

        // Release mailbox from activate command before device reboot
        if let Err(err) = soc_manager.finish_mailbox_resp(
            core::mem::size_of::<MailboxRespHeader>(),
            core::mem::size_of::<MailboxRespHeader>(),
        ) {
            match err {
                CaliptraApiError::MailboxCmdFailed(code) => {
                    romtime::println!(
                        "[mcu-rom] Error finishing mailbox command: {}",
                        HexWord(code)
                    );
                }
                _ => {
                    romtime::println!("[mcu-rom] Error finishing mailbox command");
                }
            }
            fatal_error(McuError::ROM_FW_HITLESS_UPDATE_CLEAR_MB_ERROR);
        };

        while !soc.fw_ready() {}

        // Jump to firmware
        romtime::println!("[mcu-rom] Jumping to firmware");

        #[cfg(target_arch = "riscv32")]
        unsafe {
            let firmware_entry = MCU_MEMORY_MAP.sram_offset + _params.mcu_image_header_size as u32;
            core::arch::asm!(
                "jr {0}",
                in(reg) firmware_entry,
                options(noreturn)
            );
        }

        #[cfg(not(target_arch = "riscv32"))]
        panic!("Attempting to jump to firmware on non-RISC-V platform");
    }
}
