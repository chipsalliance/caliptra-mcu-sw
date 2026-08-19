// Licensed under the Apache-2.0 license

//! Reference-platform `core_test` input-wire mapping.
//!
//! This module lives under `platforms/` so the common ROM does not depend on
//! generic input wires or the `core_test` feature. Emulator and FPGA ROMs
//! include it only in test builds.

use caliptra_mcu_registers_generated::mci::regs::Mci;
use caliptra_mcu_rom_common::{OwnerPkHashPolicy, RomParameters};
use caliptra_mcu_romtime::StaticRef;
use tock_registers::interfaces::Readable;

const SKIP_VENDOR_PK_HASH_LOCK: u32 = 1 << 0;
const ROTATE_VENDOR_PK_HASH: u32 = 1 << 1;
const FORCE_FUSE_OWNER_PK_HASH: u32 = caliptra_mcu_rom_common::FORCE_FUSE_OWNER_PK_HASH_WIRE_BIT;
const REQUEST_FLASH_BOOT: u32 = 1 << 29;
const CONTINUE_AFTER_CALIPTRA_BOOT_GO: u32 = 1 << 30;
const CONTINUE_AFTER_CALIPTRA_FUSES_WRITTEN: u32 = 1 << 31;

fn generic_input_wires_1() -> u32 {
    // Safety: `MCU_MEMORY_MAP.mci_offset` is the linker-provided MCI register
    // block base; the resulting reference is only used for typed reads.
    let mci: StaticRef<Mci> =
        unsafe { StaticRef::new(super::MCU_MEMORY_MAP.mci_offset as *const Mci) };
    mci.mci_reg_generic_input_wires[1].get()
}

fn wait_for_generic_input_wire(mask: u32) {
    while generic_input_wires_1() & mask == 0 {}
}

fn wait_after_caliptra_boot_go() {
    wait_for_generic_input_wire(CONTINUE_AFTER_CALIPTRA_BOOT_GO);
}

fn wait_after_caliptra_fuses_written() {
    wait_for_generic_input_wire(CONTINUE_AFTER_CALIPTRA_FUSES_WRITTEN);
}

/// Convert the reference test harness wires into the common ROM's explicit
/// platform configuration.
pub fn rom_parameters<'a>() -> RomParameters<'a> {
    let wires = generic_input_wires_1();
    RomParameters {
        skip_vendor_pk_hash_volatile_lock: wires & SKIP_VENDOR_PK_HASH_LOCK != 0,
        vendor_pk_hash_rotation: wires & ROTATE_VENDOR_PK_HASH != 0,
        owner_pk_hash_policy: if wires & FORCE_FUSE_OWNER_PK_HASH != 0 {
            OwnerPkHashPolicy::ForceFuse
        } else {
            OwnerPkHashPolicy::DotThenFuse
        },
        request_flash_boot: wires & REQUEST_FLASH_BOOT != 0,
        post_caliptra_boot_go: Some(wait_after_caliptra_boot_go),
        post_caliptra_fuses_written: Some(wait_after_caliptra_fuses_written),
        ..Default::default()
    }
}
