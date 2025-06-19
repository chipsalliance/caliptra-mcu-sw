// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use mcu_config::{McuMemoryMap, MemoryRegionType};

pub const FPGA_MEMORY_MAP: McuMemoryMap = McuMemoryMap {
    rom_offset: 0xb004_0000,
    rom_size: 128 * 1024,
    rom_stack_size: 0x3000,
    rom_properties: MemoryRegionType {
        side_effect: false,
        cacheable: true,
    },

    dccm_offset: 0x5000_0000,
    dccm_size: 16 * 1024,
    dccm_properties: MemoryRegionType {
        side_effect: false,
        cacheable: true,
    },

    sram_offset: 0xa8c0_0000,
    sram_size: 384 * 1024,
    sram_properties: MemoryRegionType {
        side_effect: false,
        cacheable: true,
    },

    pic_offset: 0x6000_0000,
    pic_properties: MemoryRegionType {
        side_effect: true,
        cacheable: false,
    },

    i3c_offset: 0xa403_0000,
    i3c_size: 0x1000,
    i3c_properties: MemoryRegionType {
        side_effect: true,
        cacheable: false,
    },

    mci_offset: 0xa800_0000,
    mci_size: 0xe0_0000,
    mci_properties: MemoryRegionType {
        side_effect: true,
        cacheable: false,
    },

    mbox_offset: 0xa412_0000,
    mbox_size: 0x28,
    mbox_properties: MemoryRegionType {
        side_effect: true,
        cacheable: false,
    },

    soc_offset: 0xa413_0000,
    soc_size: 0x5e0,
    soc_properties: MemoryRegionType {
        side_effect: true,
        cacheable: false,
    },

    otp_offset: 0xa406_0000,
    otp_size: 0x140,
    otp_properties: MemoryRegionType {
        side_effect: true,
        cacheable: false,
    },

    lc_offset: 0xa404_0000,
    lc_size: 0x8c,
    lc_properties: MemoryRegionType {
        side_effect: true,
        cacheable: false,
    },
};
