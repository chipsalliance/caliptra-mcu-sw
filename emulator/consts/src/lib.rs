/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains constant types related to the MCU.

--*/

use caliptra_emu_cpu::{CpuArgs, CpuOrgArgs};
use network_config::DEFAULT_NETWORK_MEMORY_MAP;

pub const DEFAULT_CPU_ARGS: CpuArgs = CpuArgs {
    org: CpuOrgArgs {
        rom: ROM_ORG,
        rom_size: ROM_SIZE,
        iccm: RAM_ORG,
        iccm_size: RAM_SIZE,
        dccm: 0x5000_0000,
        dccm_size: 256 * 1024,
        reset_vector: ROM_ORG,
    },
};

pub const RAM_ORG: u32 = 0x4000_0000;
pub const RAM_SIZE: u32 = 512 * 1024; // TEMPORARY: Increased SRAM size to accommodate integration testing
pub const ROM_ORG: u32 = 0x8000_0000;
pub const ROM_SIZE: u32 = 48 * 1024;
pub const EXTERNAL_TEST_SRAM_SIZE: u32 = 1024 * 1024;
pub const ROM_DEDICATED_RAM_ORG: u32 = 0x5000_0000;
pub const ROM_DEDICATED_RAM_SIZE: u32 = 256 * 1024;
pub const DIRECT_READ_FLASH_ORG: u32 = 0x3800_0000;
pub const DIRECT_READ_FLASH_SIZE: u32 = 64 * 1024 * 1024; // Memory-mapped primary flash (64MB)
pub const MCU_MAILBOX0_SRAM_SIZE: u32 = 2 * 1024 * 1024;
pub const MCU_MAILBOX1_SRAM_SIZE: u32 = 2 * 1024 * 1024;
pub const DOT_FLASH_SIZE: u32 = 4 * 1024; // DOT flash

// Network Coprocessor constants (re-exported from network-config for convenience)
pub const NETWORK_ROM_ORG: u32 = DEFAULT_NETWORK_MEMORY_MAP.rom_offset;
pub const NETWORK_ROM_SIZE: u32 = DEFAULT_NETWORK_MEMORY_MAP.rom_size;

/// Default CPU arguments for the Network Coprocessor
pub const NETWORK_CPU_ARGS: CpuArgs = CpuArgs {
    org: CpuOrgArgs {
        rom: DEFAULT_NETWORK_MEMORY_MAP.rom_offset,
        rom_size: DEFAULT_NETWORK_MEMORY_MAP.rom_size,
        iccm: DEFAULT_NETWORK_MEMORY_MAP.iccm_offset,
        iccm_size: DEFAULT_NETWORK_MEMORY_MAP.iccm_size,
        dccm: DEFAULT_NETWORK_MEMORY_MAP.dccm_offset,
        dccm_size: DEFAULT_NETWORK_MEMORY_MAP.dccm_size,
        reset_vector: DEFAULT_NETWORK_MEMORY_MAP.rom_offset,
    },
};
