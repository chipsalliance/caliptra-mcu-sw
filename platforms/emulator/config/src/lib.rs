// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

pub mod flash;
use mcu_config::{McuMemoryMap, McuStraps, MemoryRegionType};

pub const EMULATOR_MEMORY_MAP: McuMemoryMap = McuMemoryMap {
    rom_offset: 0x8000_0000,
    rom_size: 64 * 1024,
    rom_stack_size: 0x2d00,
    rom_estack_size: 0x200,
    rom_properties: MemoryRegionType::MEMORY,

    dccm_offset: 0x5000_0000,
    dccm_size: 16 * 1024,
    dccm_properties: MemoryRegionType::MEMORY,

    sram_offset: 0x4000_0000,
    sram_size: 512 * 1024, // TEMPORARY: Increased SRAM size to accommodate integration testing
    sram_properties: MemoryRegionType::MEMORY,

    pic_offset: 0x6000_0000,
    pic_properties: MemoryRegionType::MMIO,

    i3c_offset: 0x2000_4000,
    i3c_size: 0x1000,
    i3c_properties: MemoryRegionType::MMIO,

    i3c1_offset: 0x2000_5000,
    i3c1_size: 0x1000,
    i3c1_properties: MemoryRegionType::MMIO,

    mci_offset: 0x2100_0000,
    mci_size: 0xe0_0000,
    mci_properties: MemoryRegionType::MMIO,

    mbox_offset: 0x3002_0000,
    mbox_size: 0x28,
    mbox_properties: MemoryRegionType::MMIO,

    soc_offset: 0x3003_0000,
    soc_size: 0x5e0,
    soc_properties: MemoryRegionType::MMIO,

    otp_offset: 0x7000_0000,
    otp_size: 0x140,
    otp_properties: MemoryRegionType::MMIO,

    lc_offset: 0x7000_0400,
    lc_size: 0x8c,
    lc_properties: MemoryRegionType::MMIO,
};

const ACTIVE_I3C: u8 = if cfg!(feature = "active-i3c1") { 1 } else { 0 };

pub const EMULATOR_MCU_STRAPS: McuStraps = McuStraps {
    active_i3c: ACTIVE_I3C,
    ..McuStraps::default()
};

/// The MRAC value which should be populated for this memory map.  This corresponds to a value
/// utilized within the global start assembly and thus must be unmangled.
#[no_mangle]
pub static MRAC_VALUE: u32 = EMULATOR_MEMORY_MAP.compute_mrac();
