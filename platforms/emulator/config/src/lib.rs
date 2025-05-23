// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use mcu_config::McuMemoryMap;

pub const EMULATOR_MEMORY_MAP: McuMemoryMap = McuMemoryMap {
    rom_offset: 0x8000_0000,
    rom_size: 32 * 1024,
    rom_stack_size: 0x3000,
    dccm_offset: 0x5000_0000,
    dccm_size: 16 * 1024,
    sram_offset: 0x4000_0000,
    sram_size: 384 * 1024,
    pic_offset: 0x6000_0000,
    i3c_offset: 0x2000_4000,
    i3c_size: 0x1000,
    mci_offset: 0x2100_0000,
    mci_size: 0xe0_0000,
    mbox_offset: 0x3002_0000,
    mbox_size: 0x28,
    soc_offset: 0x3003_0000,
    soc_size: 0x5e0,
    otp_offset: 0x7000_0000,
    otp_size: 0x140,
    lc_offset: 0x7000_0400,
    lc_size: 0x8c,
};
