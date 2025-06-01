/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains constant types related to the MCU.

--*/

pub const RAM_OFFSET: u32 = 0x4000_0000;
pub const RAM_SIZE: u32 = 384 * 1024;
pub const ROM_SIZE: u32 = 48 * 1024;
pub const EXTERNAL_TEST_SRAM_SIZE: u32 = 4 * 1024;
pub const ROM_DEDICATED_RAM_OFFSET: u32 = 0x5000_0000;
pub const ROM_DEDICATED_RAM_SIZE: u32 = 0x4000;
