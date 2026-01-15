// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

pub mod flash;
use mcu_config::{McuMemoryMap, McuStraps, MemoryRegionType};

pub const FPGA_MEMORY_MAP: McuMemoryMap = McuMemoryMap {
    rom_offset: 0xb004_0000,
    rom_size: 128 * 1024,
    rom_stack_size: 0x2f00,
    rom_estack_size: 0x100,
    rom_properties: MemoryRegionType::MEMORY,

    dccm_offset: 0x5000_0000,
    dccm_size: 16 * 1024,
    dccm_properties: MemoryRegionType::MEMORY,

    sram_offset: 0xa8c0_0000,
    sram_size: 512 * 1024,
    sram_properties: MemoryRegionType::MEMORY,

    pic_offset: 0x6000_0000,
    pic_properties: MemoryRegionType::MMIO,

    i3c_offset: 0xa403_0000,
    i3c_size: 0x1000,
    i3c_properties: MemoryRegionType::MMIO,

    mci_offset: 0xa800_0000,
    mci_size: 0xa0_0028,
    mci_properties: MemoryRegionType::MMIO,

    mbox_offset: 0xa412_0000,
    mbox_size: 0x28,
    mbox_properties: MemoryRegionType::MMIO,

    soc_offset: 0xa413_0000,
    soc_size: 0x5e0,
    soc_properties: MemoryRegionType::MMIO,

    otp_offset: 0xa406_0000,
    otp_size: 0x140,
    otp_properties: MemoryRegionType::MMIO,

    lc_offset: 0xa404_0000,
    lc_size: 0x8c,
    lc_properties: MemoryRegionType::MMIO,

    staging_sram_offset: 0xb00c_0000,
    staging_sram_size: 256 * 1024,
};

pub const FPGA_MCU_STRAPS: McuStraps = McuStraps {
    i3c_static_addr: 0x3a,
    axi_user0: 0x1,
    axi_user1: 0x2,
    mcu_mbox0_axi_users: [1, 2, 0, 0, 0],
    mcu_mbox1_axi_users: [1, 2, 0, 0, 0],
    cptra_wdt_cfg0: 200_000_000,
    cptra_wdt_cfg1: 200_000_000,
    mcu_wdt_cfg0: 800_000_000, // the FPGA is slower to boot
    mcu_wdt_cfg1: 1,
};
