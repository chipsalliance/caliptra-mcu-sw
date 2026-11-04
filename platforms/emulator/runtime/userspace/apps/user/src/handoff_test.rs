// Licensed under the Apache-2.0 license

use caliptra_mcu_libsyscall_caliptra::{
    caliptra::Caliptra,
    system::{FirmwareBootType, System},
    DefaultSyscalls,
};
use caliptra_mcu_romtime::{
    handoff::{McuRomCapabilities, MCU_ROM_VERSION},
    ocp_lock::HekSeedState,
};

pub(crate) fn run() {
    let caliptra = Caliptra::<DefaultSyscalls>::new();
    let mut expected_capabilities = McuRomCapabilities::STREAMING_BOOT_I3C
        | McuRomCapabilities::OCP_LOCK
        | McuRomCapabilities::DOT_BOOT;
    if cfg!(feature = "hw-2-1") {
        expected_capabilities |= McuRomCapabilities::FLASH_BOOT;
    }

    // Only userspace syscalls are exercised here: the kernel must not acquire
    // extra handoff address references from a test hook or debug printing.
    let boot_type = System::firmware_boot_type();
    let capabilities = System::mcu_rom_capabilities();
    let version = System::mcu_rom_version();
    let state = caliptra.get_hek_active_state();
    let slot = caliptra.get_hek_active_slot();
    let total_slots = caliptra.get_hek_total_slots();
    let success = boot_type == Ok(FirmwareBootType::Streaming)
        && capabilities == Ok(expected_capabilities.bits())
        && version == Ok(MCU_ROM_VERSION)
        && state == Ok(u16::from(HekSeedState::Programmed))
        && slot == Ok(2)
        && total_slots == Ok(8);

    System::exit(u32::from(!success));
}
