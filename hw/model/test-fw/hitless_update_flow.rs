// Licensed under the Apache-2.0 license

//! A very simple program that follows hitless update flows. Must be used with corresponding
//! Caliptra program.

#![no_main]
#![no_std]

use mcu_error::McuError;
use mcu_rom_common::{fatal_error, fatal_error_raw, McuBootMilestones, RomEnv};
use registers_generated::mci;
use romtime::McuResetReason;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

// Needed to bring in startup code
#[allow(unused)]
use mcu_test_harness;

fn wait_for_firmware_ready(mci: &romtime::Mci, cptra: &mcu_rom_common::Soc) {
    let notif0 = &mci.registers.intr_block_rf_notif0_internal_intr_r;
    // Wait for a reset request from Caliptra
    while !notif0.is_set(mci::bits::Notif0IntrT::NotifCptraMcuResetReqSts) {
        if cptra.cptra_fw_fatal_error() {
            romtime::println!("[mcu-rom] Caliptra reported a fatal error");
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
    romtime::println!("[mcu-rom] Setting Caliptra boot go");
    mci.caliptra_boot_go();
    mci.set_flow_milestone(McuBootMilestones::CPTRA_BOOT_GO_ASSERTED.into());
    romtime::println!(
        "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
        cptra.ready_for_fuses()
    );
    while !cptra.ready_for_fuses() {}
    romtime::println!("[mcu-rom] Setting Caliptra fuse write done");
    cptra.fuse_write_done();

    // Wait for "firmware" to be ready
    wait_for_firmware_ready(mci, cptra);

    // Check for known pattern from Caliptra test ROM
    if mci.registers.mcu_sram[0].get() != u32::from_be_bytes(*b"BFOR") {
        romtime::println!(
            "Expected 0xBFOR, got 0x{:08x}",
            mci.registers.mcu_sram[0].get()
        );
        fatal_error_raw(1);
    }

    // Notify Caliptra to continue
    mci.registers.mcu_sram[0].set(u32::from_be_bytes(*b"CONT"));

    // Wait for "hitlesss update" to be ready
    wait_for_firmware_ready(mci, cptra);

    romtime::println!("[mcu-rom] hitless update ready");
    mci.set_flow_milestone(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE.into());
    mci.trigger_warm_reset();
    loop {}
}

fn hitless_update(env: &mut RomEnv) -> ! {
    let mci = &env.mci;

    // Check for updated known pattern
    if mci.registers.mcu_sram[0].get() != u32::from_be_bytes(*b"AFTR") {
        romtime::println!(
            "Expected AFTR, got 0x{:08x}",
            mci.registers.mcu_sram[0].get()
        );
        fatal_error_raw(2);
    }
    mci.set_flow_milestone(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE.into());
    loop {}
}

fn run() -> ! {
    let mut env = RomEnv::new();

    match env.mci.reset_reason_enum() {
        McuResetReason::ColdBoot => {
            romtime::println!("[mcu-rom] Cold boot detected");
            cold_boot(&mut env);
        }
        McuResetReason::FirmwareHitlessUpdate => {
            romtime::println!("[mcu-rom] Starting firmware hitless update flow");
            hitless_update(&mut env);
        }
        reason => {
            romtime::println!("[mcu-rom] Invalid reset reason {reason:?}");
            fatal_error(McuError::ROM_ROM_INVALID_RESET_REASON);
        }
    }
}

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    run();
}
