// Licensed under the Apache-2.0 license

//! A very simple program that follows hitless update flows. Must be used with corresponding
//! Caliptra program.

#![no_main]
#![no_std]

use caliptra_mcu_error::McuError;
use caliptra_mcu_registers_generated::mci;
use caliptra_mcu_rom_common::{fatal_error, RomEnv};
use caliptra_mcu_romtime::McuBootMilestones;
use caliptra_mcu_romtime::McuResetReason;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

fn wait_for_firmware_ready(mci: &caliptra_mcu_romtime::Mci, cptra: &caliptra_mcu_rom_common::Soc) {
    let notif0 = &mci.registers.intr_block_rf_notif0_internal_intr_r;
    // Wait for a reset request from Caliptra
    while !notif0.is_set(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts) {
        if cptra.cptra_fw_fatal_error() {
            caliptra_mcu_romtime::println!("[mcu-rom] Caliptra reported a fatal error");
            fatal_error(McuError::ROM_COLD_BOOT_CALIPTRA_FATAL_ERROR_BEFORE_MB_READY);
        }
    }
    // Clear the reset request interrupt
    notif0.modify(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts::SET);
}

fn cold_boot(env: &mut RomEnv) -> ! {
    let mci = &env.mci;
    let cptra = &env.soc;

    // Release Caliptra from reset because we need to use its test ROM
    caliptra_mcu_romtime::println!("[mcu-rom] Setting Caliptra boot go");
    mci.caliptra_boot_go();
    mci.set_flow_milestone(McuBootMilestones::CPTRA_BOOT_GO_ASSERTED.into());
    caliptra_mcu_romtime::println!(
        "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
        cptra.ready_for_fuses()
    );
    while !cptra.ready_for_fuses() {}
    caliptra_mcu_romtime::println!("[mcu-rom] Setting Caliptra fuse write done");
    cptra.fuse_write_done();

    // Wait for "firmware" to be ready
    wait_for_firmware_ready(mci, cptra);

    // Check for known pattern from Caliptra test ROM
    if mci.registers.mcu_sram[0].get() != u32::from_be_bytes(*b"BFOR") {
        caliptra_mcu_romtime::println!(
            "Expected 0xBFOR, got 0x{:08x}",
            mci.registers.mcu_sram[0].get()
        );
        fatal_error(HitlessUpdateError::InvalidBeforeValue.into());
    }

    // Notify Caliptra to continue
    mci.registers.mcu_sram[0].set(u32::from_be_bytes(*b"CONT"));

    // Wait for "hitlesss update" to be ready
    wait_for_firmware_ready(mci, cptra);

    caliptra_mcu_romtime::println!("[mcu-rom] hitless update ready");
    mci.set_flow_milestone(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE.into());
    mci.trigger_warm_reset();
    #[allow(clippy::empty_loop)] // Ok to waste CPU cycles waiting for test to end
    loop {}
}

fn hitless_update(env: &mut RomEnv) -> ! {
    let mci = &env.mci;

    // Check for updated known pattern
    if mci.registers.mcu_sram[0].get() != u32::from_be_bytes(*b"AFTR") {
        caliptra_mcu_romtime::println!(
            "Expected AFTR, got 0x{:08x}",
            mci.registers.mcu_sram[0].get()
        );
        fatal_error(HitlessUpdateError::InvalidAfterValue.into());
    }
    mci.set_flow_milestone(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE.into());
    #[allow(clippy::empty_loop)] // Ok to waste CPU cycles waiting for test to end
    loop {}
}

fn run() -> ! {
    let mut env = RomEnv::new();

    match env.mci.reset_reason_enum() {
        McuResetReason::ColdBoot => {
            caliptra_mcu_romtime::println!("[mcu-rom] Cold boot detected");
            cold_boot(&mut env);
        }
        McuResetReason::FirmwareHitlessUpdate => {
            caliptra_mcu_romtime::println!("[mcu-rom] Starting firmware hitless update flow");
            hitless_update(&mut env);
        }
        reason => {
            caliptra_mcu_romtime::println!("[mcu-rom] Invalid reset reason {reason:?}");
            fatal_error(McuError::ROM_ROM_INVALID_RESET_REASON);
        }
    }
}

#[no_mangle]
pub extern "C" fn main() {
    caliptra_mcu_test_harness::set_printer();
    run();
}

enum HitlessUpdateError {
    InvalidBeforeValue,
    InvalidAfterValue,
}

impl From<HitlessUpdateError> for caliptra_mcu_error::McuError {
    fn from(err: HitlessUpdateError) -> Self {
        McuError::new_vendor(err as u32)
    }
}
